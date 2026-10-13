import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { z } from "zod";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import type { BinjaConfiguration } from "./BinjaConfiguration.js";
import { binjaToolFailureSchema } from "./BinjaProtocolValues.js";

/** Injectable MCP boundary used by the provider, operator tooling, and tests. */
export interface BinjaMcpConnection {
  connect(): Promise<readonly string[]>;
  /** A structured reply decodes to its object, a text reply to its one string. */
  call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
    options?: { readonly timeoutMs?: number },
  ): Promise<JsonValue>;
  serverInfo(): JsonValue;
  close(): Promise<void>;
}

/** Binary Ninja refused one tool call and named its reason. */
export class BinjaToolError extends AnalysisProtocolError {
  constructor(
    readonly tool: string,
    readonly code: string,
    readonly reason: string,
  ) {
    super(`Binary Ninja MCP tool ${tool} failed (${code}): ${reason}`);
  }
}

const toolResultSchema = z.object({
  isError: z.boolean().optional(),
  structuredContent: z.record(z.string(), z.unknown()).optional(),
  content: z
    .array(z.looseObject({ type: z.string(), text: z.string().optional() }))
    .default([]),
});

/** Decode one tool result without inventing an empty observation. */
export const decodeBinjaToolResult = (
  tool: string,
  input: unknown,
): JsonValue => {
  const result = toolResultSchema.parse(input);
  const blocks = result.content.flatMap((block) =>
    block.type === "text" && block.text !== undefined ? [block.text] : [],
  );
  if (result.isError === true) {
    const failure = binjaToolFailureSchema.safeParse(result.structuredContent);
    throw failure.success
      ? new BinjaToolError(
          tool,
          failure.data.errorCode,
          failure.data.errorMessage,
        )
      : new BinjaToolError(
          tool,
          "unreported",
          blocks.join("\n") || "unexplained failure",
        );
  }
  if (result.structuredContent !== undefined)
    return jsonValueSchema.parse(result.structuredContent);
  if (blocks.length !== 1)
    throw new AnalysisProtocolError(
      `Binary Ninja MCP tool ${tool} omitted a single structured or text result; unsupported content cannot establish an empty observation.`,
    );
  return blocks[0] ?? "";
};

/**
 * Create a Streamable HTTP connection to an already running Binary Ninja.
 *
 * `allowedTools` is the complete authority of this connection: a call to any
 * other tool is refused before it reaches the network, so a read-only caller
 * cannot save, close, open, or edit by mistake.
 */
export const createBinjaMcpConnection = (
  config: BinjaConfiguration,
  allowedTools: ReadonlySet<string>,
): BinjaMcpConnection => {
  const client = new Client({ name: "rea-binja-provider", version: "1" });
  const transport = new StreamableHTTPClientTransport(new URL(config.url), {
    requestInit: { redirect: "error" },
  });
  return {
    async connect() {
      await client.connect(transport, { timeout: config.timeoutMs });
      const catalog = await client.listTools(undefined, {
        timeout: config.timeoutMs,
      });
      return catalog.tools.map(({ name }) => name);
    },
    async call(name, args, options) {
      if (!allowedTools.has(name))
        throw new AnalysisProtocolError(
          `Binary Ninja MCP tool ${name} is outside this connection's authority and was not called.`,
        );
      return decodeBinjaToolResult(
        name,
        await client.callTool(
          { name, arguments: args },
          { timeout: options?.timeoutMs ?? config.timeoutMs },
        ),
      );
    },
    serverInfo: () => jsonValueSchema.parse(client.getServerVersion() ?? null),
    close: () => client.close(),
  };
};
