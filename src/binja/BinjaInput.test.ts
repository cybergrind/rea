import { describe, expect, it } from "vitest";
import type { JsonValue } from "../domain/jsonValue.js";
import { parseBinjaInput } from "./BinjaInput.js";

const rejected = (
  operation: string,
  parameters: Readonly<Record<string, JsonValue>>,
) => {
  const parsed = parseBinjaInput(operation, parameters);
  if (parsed.ok) throw new Error(`${operation} input unexpectedly accepted`);
  return parsed.error;
};

describe("Binary Ninja operation input", () => {
  it("applies the public contract defaults", () => {
    const bytes = parseBinjaInput("read_bytes", { address: "0x1000" });
    if (!bytes.ok) throw bytes.error;
    expect(bytes.value).toEqual({ address: "0x1000", length: 256 });
    const references = parseBinjaInput("procedure_references", {
      procedure: "main",
    });
    if (!references.ok) throw references.error;
    expect(references.value).toEqual({
      procedure: "main",
      direction: "outgoing",
    });
  });

  it.each(["xrefs", "address_name", "comment"])(
    "requires an explicit address for %s because there is no cursor",
    (operation) => {
      expect(rejected(operation, {}).issues).toMatchObject([
        { path: ["address"], reason: "missing_argument" },
      ]);
    },
  );

  it("rejects a non-hexadecimal address, an empty procedure, and a broken regex", () => {
    expect(rejected("read_bytes", { address: "main+4" }).issues).toMatchObject([
      { path: ["address"], reason: "invalid_format" },
    ]);
    expect(
      rejected("procedure_pseudo_code", { procedure: "" }).issues,
    ).toMatchObject([{ path: ["procedure"], reason: "invalid_value" }]);
    const regex = rejected("search_strings", { pattern: "(", mode: "regex" });
    expect(regex.issues).toMatchObject([
      { path: ["pattern"], reason: "invalid_format" },
    ]);
    expect(regex.cause).toBeInstanceOf(SyntaxError);
    const literal = parseBinjaInput("search_strings", { pattern: "(" });
    if (!literal.ok) throw literal.error;
    expect(literal.value.mode).toBe("literal");
  });

  it("rejects an unknown operation and contract-invalid parameters", () => {
    expect(rejected("not_an_operation", {})._tag).toBe("AnalysisInputError");
    expect(
      rejected("procedure_pseudo_code", { procedure: "main", extra: 1 }).issues,
    ).toMatchObject([{ reason: "unknown_argument" }]);
    expect(rejected("read_bytes", { address: "0x1", length: 0 })._tag).toBe(
      "AnalysisInputError",
    );
  });
});
