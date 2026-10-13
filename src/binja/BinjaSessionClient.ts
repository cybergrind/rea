import { z } from "zod";
import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisOperation,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import { parseBinjaInput } from "./BinjaInput.js";
import {
  BinjaToolError,
  type BinjaMcpConnection,
} from "./BinjaMcpConnection.js";
import { BinjaOperationRunner } from "./BinjaOperationRunner.js";
import {
  BINJA_LIMITATIONS,
  BINJA_OPERATIONS,
  BINJA_PROVIDER_IDENTITY,
  BINJA_READ_ONLY_TOOLS,
  BINJA_UNSUPPORTED_OPERATIONS,
  binjaLimitationsFor,
  type BinjaOperation,
} from "./BinjaProviderCapabilities.js";
import { BinjaTargetBinding, sameBinjaHostPath } from "./BinjaTargetBinding.js";

const operationSet: ReadonlySet<string> = new Set(BINJA_OPERATIONS);
const isBinjaOperation = (operation: string): operation is BinjaOperation =>
  operationSet.has(operation);
const refusals = new Map<string, string>(BINJA_UNSUPPORTED_OPERATIONS);
const wasCancelled = (options: ExecutionOptions | undefined): boolean =>
  options?.signal?.aborted === true;

/** Serial read-only session over the active view of an attached Binary Ninja. */
export class BinjaSessionClient implements AnalysisClient {
  #tail: Promise<void> = Promise.resolve();
  #startup: Promise<void> | undefined;
  #connected = false;
  #closed = false;
  #closing = false;
  readonly #binding: BinjaTargetBinding;

  constructor(
    private readonly target: BinaryTarget,
    private readonly connection: BinjaMcpConnection,
    private readonly profile?: AnalysisProfileCommitment,
  ) {
    this.#binding = new BinjaTargetBinding(connection, target);
  }

  /** Binary Ninja answers one caller at a time, so requests never overlap. */
  execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    const call = this.#tail.then(() =>
      this.#execute(operation, parameters, options),
    );
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    return call;
  }

  #refusal(operation: AnalysisOperation, document: JsonValue | undefined) {
    if (this.#closed || this.#closing)
      return new AnalysisProtocolError(
        "Binary Ninja session is closing or closed; reopen the target.",
      );
    if (operation !== "health" && !isBinjaOperation(operation))
      return new AnalysisCapabilityUnavailableError(
        "binja",
        operation,
        refusals.get(operation) ??
          "This integration admits read-only native analysis operations only.",
      );
    if (
      document !== undefined &&
      (typeof document !== "string" ||
        (!sameBinjaHostPath(document, this.target.path) &&
          (this.target.sourcePath === undefined ||
            !sameBinjaHostPath(document, this.target.sourcePath))))
    )
      return new AnalysisInputError(operation, undefined, [
        {
          path: ["document"],
          reason: "invalid_value",
          expected: this.target.path,
          message:
            "Binary Ninja document must be the REA-bound target; omit document or use its admitted path.",
        },
      ]);
    return undefined;
  }

  async #execute(
    operation: AnalysisOperation,
    input: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    if (wasCancelled(options))
      return err(new AnalysisCancelledError(operation));
    const refusal = this.#refusal(operation, input.document);
    if (refusal !== undefined) return err(refusal);
    let parameters = input;
    if (operation !== "health") {
      const parsed = parseBinjaInput(operation, input);
      if (!parsed.ok) return parsed;
      parameters = parsed.value;
    }
    try {
      await this.#start();
      const before = await this.#binding.observe();
      if (wasCancelled(options))
        return err(new AnalysisCancelledError(operation));
      if (operation === "health" || !isBinjaOperation(operation))
        return this.#health(before);
      const runner = new BinjaOperationRunner(
        this.connection,
        this.target,
        options?.signal,
      );
      const result = await runner.run(operation, parameters);
      const after = await this.#binding.observe();
      if (wasCancelled(options))
        return err(new AnalysisCancelledError(operation));
      return ok(
        createAnalysisExecution(result, BINJA_PROVIDER_IDENTITY, {
          rawResult: {
            upstream: this.connection.serverInfo(),
            view_before: before,
            view_after: after,
            observations: jsonValueSchema.parse(runner.reader.raw),
          },
          limitations: [
            ...binjaLimitationsFor(operation),
            ...this.#binding.limitations,
            ...runner.reader.limitations,
          ],
          locations: [
            { kind: "artifact-path", path: this.target.path },
            ...runner.reader.locations,
          ],
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        }),
      );
    } catch (cause: unknown) {
      return this.#failure(operation, cause, options);
    }
  }

  #health(view: JsonValue) {
    return ok(
      createAnalysisExecution(
        { ready: true, upstream: this.connection.serverInfo(), view },
        BINJA_PROVIDER_IDENTITY,
        {
          limitations: [...BINJA_LIMITATIONS, ...this.#binding.limitations],
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        },
      ),
    );
  }

  #failure(
    operation: string,
    cause: unknown,
    options: ExecutionOptions | undefined,
  ) {
    if (wasCancelled(options))
      return err(new AnalysisCancelledError(operation));
    // A refusal carries Binary Ninja's own reason, which the caller can act on.
    if (cause instanceof BinjaToolError)
      return err(
        new ProviderAdapterError("binja", operation, {
          cause,
          userMessage: `Binary Ninja refused ${cause.tool} (${cause.code}): ${cause.reason}`,
          diagnostics: {
            reason: cause.reason,
            upstream_tool: cause.tool,
            upstream_code: cause.code,
          },
        }),
      );
    if (cause instanceof AnalysisError) return err(cause);
    if (cause instanceof z.ZodError)
      return err(
        new AnalysisOutputError(
          operation,
          `Binary Ninja MCP returned malformed or unsupported producer data: ${cause.issues.map((issue) => `${issue.path.join(".") || "$"}: ${issue.message}`).join("; ")}`,
          { cause },
        ),
      );
    const reason =
      cause instanceof Error ? cause.message : "Unknown upstream failure";
    const recovery =
      "Check that Binary Ninja is running with its MCP server at REA_BINJA_MCP_URL and that the target's view is active; see docs/binja-provider.md.";
    return err(
      new ProviderAdapterError("binja", operation, {
        cause,
        userMessage: `The Binary Ninja MCP request failed: ${reason}. ${recovery}`,
        diagnostics: { reason, recovery },
      }),
    );
  }

  #start(): Promise<void> {
    this.#startup ??= this.#initialize();
    return this.#startup;
  }

  async #initialize(): Promise<void> {
    this.#connected = true;
    const tools = new Set(await this.connection.connect());
    const missing = [...BINJA_READ_ONLY_TOOLS].filter(
      (name) => !tools.has(name),
    );
    if (missing.length > 0)
      throw new ProviderAdapterError("binja", "connect", {
        userMessage: `The Binary Ninja MCP server is missing tools this adapter requires: ${missing.join(", ")}. See docs/binja-provider.md.`,
        diagnostics: {
          reason: "The MCP server does not advertise every required tool.",
          missing_tools: missing,
        },
      });
  }

  /** Release the MCP connection only; the GUI database is never saved or closed. */
  async close(): Promise<Result<null, AnalysisError>> {
    this.#closing = true;
    await this.#tail;
    if (this.#closed || !this.#connected) {
      this.#closed = true;
      return ok(null);
    }
    try {
      await this.connection.close();
      this.#closed = true;
      return ok(null);
    } catch (cause: unknown) {
      return err(
        new ProviderAdapterError("binja", "close", {
          cause,
          diagnostics: {
            reason:
              cause instanceof Error
                ? cause.message
                : "Unknown connection failure",
          },
        }),
      );
    }
  }
}
