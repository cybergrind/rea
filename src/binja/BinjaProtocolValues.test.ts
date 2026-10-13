import { describe, expect, it } from "vitest";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import {
  binjaAddressSchema,
  parseBinjaFunctionReferences,
  parseBinjaRange,
  parseBinjaText,
  splitBinjaCell,
} from "./BinjaProtocolValues.js";

const listing = [
  "---",
  'tool: "bn_function_callers"',
  'function: "0x2000"',
  'arch: "x86_64"',
  'name: "ns::helper(int32_t value)"',
  "offset: 0",
  "limit: 1000",
  "count: 1",
  "total: 1",
  "nextOffset: null",
  "truncated: false",
  "---",
  "",
  "| Callsite | Architecture | Caller Function |",
  "| --- | --- | --- |",
  "| 0x1004 | x86_64 | main (0x1000 (x86_64)) |",
  "",
].join("\n");

describe("Binary Ninja text replies", () => {
  it("parses front matter scalars and one table", () => {
    const reply = parseBinjaText(listing);
    expect(reply.meta).toMatchObject({
      tool: "bn_function_callers",
      function: "0x2000",
      offset: 0,
      nextOffset: null,
      truncated: false,
    });
    expect(reply.block).toBeNull();
    expect(reply.tables).toEqual([
      {
        heading: null,
        headers: ["Callsite", "Architecture", "Caller Function"],
        rows: [
          {
            Callsite: "0x1004",
            Architecture: "x86_64",
            "Caller Function": "main (0x1000 (x86_64))",
          },
        ],
      },
    ]);
  });

  it("keeps an empty table, titled sections, and escaped pipes apart", () => {
    const reply = parseBinjaText(
      [
        "---",
        'tool: "bn_function_info"',
        "---",
        "",
        "## Function",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Name | operator\\|(int32_t) |",
        "| Trailing | ends with \\| |",
        "",
        "## Basic Blocks",
        "",
        "| Index | Range |",
        "| --- | --- |",
        "",
      ].join("\n"),
    );
    expect(reply.tables.map(({ heading }) => heading)).toEqual([
      "Function",
      "Basic Blocks",
    ]);
    expect(reply.tables[0]?.rows).toEqual([
      { Field: "Name", Value: "operator|(int32_t)" },
      { Field: "Trailing", Value: "ends with |" },
    ]);
    expect(reply.tables[1]?.rows).toEqual([]);
  });

  it("returns a fenced block verbatim, including blank and indented lines", () => {
    const reply = parseBinjaText(
      '---\ntool: "bn_function_decompile"\n---\n\n````bn-pseudoc\n  int32_t main()\n\n{\n    return 0;\n}\n````\n',
    );
    expect(reply.block).toBe("  int32_t main()\n\n{\n    return 0;\n}");
    expect(reply.tables).toEqual([]);
  });

  it.each([
    ["missing front matter", "| a |\n| --- |\n"],
    ["malformed front matter line", "---\nno separator here\n---\n"],
    ["unterminated front matter", '---\ntool: "x"\n'],
    [
      "unterminated code block",
      '---\ntool: "x"\n---\n\n````asm\n0x1000  ret\n',
    ],
    [
      "a table row has 3 cells where 2 were declared",
      '---\ntool: "x"\n---\n\n| a | b |\n| --- | --- |\n| 1 | 2 | 3 |\n',
    ],
    [
      "unexpected body line outside a table",
      '---\ntool: "x"\n---\n\nResult was cut by the transport\n',
    ],
  ])("rejects a reply with %s", (reason, text) => {
    expect(() => parseBinjaText(text)).toThrow(AnalysisProtocolError);
    expect(() => parseBinjaText(text)).toThrow(reason);
  });
});

describe("Binary Ninja cell values", () => {
  it("decodes a half-open range and rejects one that contradicts itself", () => {
    expect(parseBinjaRange("0x1000-0x1010 (16 bytes)")).toEqual({
      start: 0x1000n,
      end: 0x1010n,
    });
    expect(
      parseBinjaRange("0x18d7f7950-0x18d7f865f (3343 bytes) fallthrough"),
    ).toEqual({ start: 0x18d7f7950n, end: 0x18d7f865fn });
    for (const text of [
      "0x1000-0x1010 (15 bytes)",
      "0x1010-0x1000 (16 bytes)",
      "0x1000-0x1000 (0 bytes)",
      "0x1000",
    ])
      expect(() => parseBinjaRange(text)).toThrow(AnalysisProtocolError);
  });

  it("decodes function cells with nested parentheses and several functions", () => {
    expect(parseBinjaFunctionReferences("")).toEqual([]);
    expect(
      parseBinjaFunctionReferences(
        "ns::a(struct ns::T* this, void (*)(int32_t)) (0x1000 (x86_64)), sub_2000 (0X2000 (thumb2))",
      ),
    ).toEqual([
      {
        address: "0x1000",
        name: "ns::a(struct ns::T* this, void (*)(int32_t))",
      },
      { address: "0x2000", name: "sub_2000" },
    ]);
    expect(() => parseBinjaFunctionReferences("0x1000")).toThrow(
      AnalysisProtocolError,
    );
  });

  it("splits multi-valued cells on every <br> spelling", () => {
    expect(splitBinjaCell("a<br>b<BR/>c<br />d")).toEqual(["a", "b", "c", "d"]);
    expect(splitBinjaCell("")).toEqual([]);
    expect(splitBinjaCell(" only ")).toEqual(["only"]);
  });

  it("normalizes addresses without losing bits above 2^53", () => {
    expect(binjaAddressSchema.parse("0x1000")).toBe("0x1000");
    expect(binjaAddressSchema.parse("1000")).toBe("0x1000");
    expect(binjaAddressSchema.parse("0X00ABCDEF")).toBe("0xabcdef");
    expect(binjaAddressSchema.parse("0xFFFFFFFFFFFFFFFF")).toBe(
      "0xffffffffffffffff",
    );
    expect(binjaAddressSchema.parse("0x20000000000001")).toBe(
      "0x20000000000001",
    );
    for (const invalid of ["", "0x", "main", "0x10g", "-0x10"])
      expect(binjaAddressSchema.safeParse(invalid).success).toBe(false);
  });
});
