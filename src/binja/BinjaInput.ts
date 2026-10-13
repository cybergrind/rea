import { TOOL_CONTRACTS } from "../contracts/toolContracts.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { projectInputIssues } from "../domain/inputIssueProjection.js";
import { jsonObjectSchema, type JsonValue } from "../domain/jsonValue.js";
import { err, ok } from "../domain/result.js";
import { binjaAddressSchema } from "./BinjaProtocolValues.js";

/** Operations that cannot default to a GUI cursor and need an explicit address. */
const ADDRESS_REQUIRED: ReadonlySet<string> = new Set([
  "xrefs",
  "address_name",
  "comment",
]);

const issue = (
  operation: string,
  path: string,
  detail: {
    readonly reason: "missing_argument" | "invalid_format" | "invalid_value";
    readonly message: string;
    readonly cause?: unknown;
  },
) =>
  err(
    new AnalysisInputError(
      operation,
      detail.cause === undefined ? undefined : { cause: detail.cause },
      [{ path: [path], reason: detail.reason, message: detail.message }],
    ),
  );

/** Apply the named public contract and Binary Ninja's explicit-address boundary. */
export const parseBinjaInput = (
  operation: string,
  parameters: Readonly<Record<string, JsonValue>>,
) => {
  const contract = TOOL_CONTRACTS.find(({ name }) => name === operation);
  const parsed = contract?.inputSchema.safeParse(parameters);
  if (parsed?.success !== true)
    return err(
      new AnalysisInputError(
        operation,
        { cause: parsed?.error },
        parsed?.error === undefined
          ? []
          : projectInputIssues(parsed.error.issues, parameters),
      ),
    );
  if (ADDRESS_REQUIRED.has(operation) && typeof parameters.address !== "string")
    return issue(operation, "address", {
      reason: "missing_argument",
      message:
        "Binary Ninja has no cursor to default to; supply a hexadecimal address.",
    });
  if (
    parameters.address !== undefined &&
    !binjaAddressSchema.safeParse(parameters.address).success
  )
    return issue(operation, "address", {
      reason: "invalid_format",
      message: "Binary Ninja requires a hexadecimal address.",
    });
  if (
    typeof parameters.procedure === "string" &&
    parameters.procedure.length === 0
  )
    return issue(operation, "procedure", {
      reason: "invalid_value",
      message: "Supply a function name or address.",
    });
  if (parameters.mode === "regex" && typeof parameters.pattern === "string") {
    try {
      new RegExp(
        parameters.pattern,
        parameters.case_sensitive === true ? "u" : "iu",
      );
    } catch (cause: unknown) {
      return issue(operation, "pattern", {
        reason: "invalid_format",
        message: "Supply a valid regular expression.",
        cause,
      });
    }
  }
  return ok(jsonObjectSchema.parse(parsed.data));
};
