import { describe, expect, it } from "vitest";
import {
  BinjaProducerFixture,
  binjaPage,
  binjaTarget,
} from "../../tests/fixtures/binjaMcp.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { functionDossierSchema } from "../domain/hopperValues.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { BinjaOperationRunner } from "./BinjaOperationRunner.js";
import type { BinjaOperation } from "./BinjaProviderCapabilities.js";

const fixture = () => {
  const target = binjaTarget();
  const producer = new BinjaProducerFixture(target);
  const run = async (
    operation: BinjaOperation,
    parameters: Readonly<Record<string, JsonValue>> = {},
  ) => {
    const runner = new BinjaOperationRunner(producer, target);
    const result = await runner.run(operation, parameters);
    return { result, limitations: runner.reader.limitations.join(" "), runner };
  };
  return { target, producer, run };
};
const search = (pattern: string, extra: Record<string, JsonValue> = {}) => ({
  pattern,
  mode: "literal",
  case_sensitive: false,
  ...extra,
});
const requests = (producer: BinjaProducerFixture, tool: string) =>
  producer.calls.filter(({ name }) => name === tool).map(({ args }) => args);

describe("Binary Ninja string observations", () => {
  it("confirms a match beyond the 256-byte preview by reading the object's bytes", async () => {
    const { producer, run } = fixture();
    const found = await run("search_strings", search("NEEDLE-in-the-tail"));
    expect(found.result).toEqual([
      {
        address: "0x3100",
        value: producer.longString,
        provider_value: producer.longString.slice(0, 256),
      },
    ]);
    expect(requests(producer, "bn_string_list")).toEqual([
      {
        previewBytes: 256,
        query: "NEEDLE-in-the-tail",
        offset: 0,
        limit: 1000,
      },
    ]);
    expect(requests(producer, "bn_memory_read")).toEqual([
      { address: "0x3100", length: producer.longString.length },
    ]);
    expect(found.limitations).toContain("preselected");
    expect(found.limitations).not.toContain("are cut");
  });

  it("reports a cut value when the whole object cannot be read", async () => {
    const { producer, run } = fixture();
    producer.overrideCall = (name) =>
      name === "bn_memory_read"
        ? { address: "0x3100", bytesRead: 0, hex: "", warnings: [] }
        : undefined;
    const one = await run("list_strings", { address: "0x3100" });
    expect(one.result).toEqual([{ address: "0x3100", value: "x".repeat(256) }]);
    expect(one.limitations).toContain(
      "1 returned string value(s) are cut at the first 256 bytes",
    );
    // The local recheck then cannot see a match that lies beyond the preview.
    const missed = await run("search_strings", search("needle"));
    expect(missed.result).toEqual([]);
  });

  it("lists previews without reading each object and marks cut values", async () => {
    const { producer, run } = fixture();
    const listed = await run("list_strings");
    expect(listed.result).toEqual([
      { address: "0x3000", value: "a.b\nC", provider_value: "a.b\\nC" },
      { address: "0x3100", value: "x".repeat(256) },
      { address: "0x3400", value: "hi" },
    ]);
    expect(requests(producer, "bn_memory_read")).toEqual([]);
    expect(listed.limitations).toContain("1 returned string value(s) are cut");
  });

  it("decodes UTF-16 and UTF-32 and keeps display text for undecodable bytes", async () => {
    const { producer, run } = fixture();
    producer.strings = [
      {
        address: "0x3400",
        type: "Utf16String",
        bytes: Buffer.from("héllo €", "utf16le"),
        display: "h\\xe9llo \\u20ac",
      },
      {
        address: "0x3500",
        type: "Utf32String",
        bytes: Buffer.from("680000003dd80000", "hex"),
        display: "h\\ud83d",
      },
      {
        address: "0x3600",
        type: "Utf32String",
        bytes: Buffer.from("6800000042f60100", "hex"),
        display: "h\\U0001f642",
      },
      {
        address: "0x3700",
        type: "AsciiString",
        bytes: Buffer.from("c3286f6b", "hex"),
        display: "\\xc3(ok",
      },
      {
        address: "0x3800",
        type: "Utf32String",
        bytes: Buffer.from("680000", "hex"),
        display: "h?",
      },
    ];
    const listed = await run("list_strings");
    expect(listed.result).toEqual([
      {
        address: "0x3400",
        value: "héllo €",
        provider_value: "h\\xe9llo \\u20ac",
      },
      {
        address: "0x3500",
        value: "h\\ud83d",
        decoding: {
          available: false,
          reason: expect.stringContaining("Utf32String bytes do not decode"),
        },
      },
      { address: "0x3600", value: "h🙂", provider_value: "h\\U0001f642" },
      {
        address: "0x3700",
        value: "\\xc3(ok",
        decoding: {
          available: false,
          reason: expect.stringContaining("AsciiString bytes do not decode"),
        },
      },
      {
        address: "0x3800",
        value: "h?",
        decoding: { available: false, reason: expect.any(String) },
      },
    ]);
  });
});

describe("Binary Ninja search strategy", () => {
  it("passes an ASCII literal upstream and rechecks case locally", async () => {
    const { producer, run } = fixture();
    const insensitive = await run("search_procedures", search("HELPER"));
    expect(insensitive.result).toEqual([
      { address: "0x2000", value: "ns::helper(int32_t value)" },
    ]);
    expect(insensitive.limitations).toContain("preselected");
    const sensitive = await run(
      "search_procedures",
      search("HELPER", { case_sensitive: true }),
    );
    expect(sensitive.result).toEqual([]);
    expect(requests(producer, "bn_function_list")).toEqual([
      { query: "HELPER", offset: 0, limit: 1000 },
      { query: "HELPER", offset: 0, limit: 1000 },
    ]);
  });

  it.each([
    ["a regex", search("^ma.n$", { mode: "regex" }), ["0x1000"]],
    ["a literal with a table delimiter", search("a|b"), []],
    ["a literal with a backslash", search("a\\b"), []],
    ["a non-ASCII literal", search("héllo"), []],
  ])("walks every function for %s", async (_label, query, addresses) => {
    const { producer, run } = fixture();
    const found = await run("search_procedures", query);
    expect(found.result).toEqual(
      addresses.map((address) => expect.objectContaining({ address })),
    );
    expect(requests(producer, "bn_function_list")).toEqual([
      { offset: 0, limit: 1000 },
    ]);
    expect(found.limitations).not.toContain("preselected");
  });

  it("matches a regex against previews only and says so", async () => {
    const { producer, run } = fixture();
    const found = await run(
      "search_strings",
      search("needle", { mode: "regex" }),
    );
    expect(found.result).toEqual([]);
    expect(found.limitations).toContain("first 256 bytes only");
    expect(requests(producer, "bn_string_list")).toEqual([
      { previewBytes: 256, offset: 0, limit: 1000 },
    ]);
  });
});

describe("Binary Ninja address observations", () => {
  it("maps file-backed addresses and rejects ones without file bytes", async () => {
    const { run } = fixture();
    expect(
      (await run("address_to_file_offset", { address: "0x3010" })).result,
    ).toEqual({
      address: "0x3010",
      file_offset: 0x2010,
    });
    for (const address of ["0x3800", "0x4000", "0x9000"]) {
      const failure = run("address_to_file_offset", { address });
      await expect(failure).rejects.toThrow(AnalysisInputError);
      await expect(failure).rejects.toMatchObject({
        issues: [{ path: ["address"], reason: "invalid_value" }],
      });
    }
  });

  it("reports call sites and data references for a function entry", async () => {
    const { run } = fixture();
    const entry = await run("xrefs", { address: "0x2000" });
    expect(entry.result).toEqual(["0x1004", "0x3800"]);
    expect(entry.limitations).toContain("non-call code references");
    expect(entry.runner.reader.locations).toEqual([
      { kind: "address", address: "0x2000" },
    ]);
  });

  it("records that code references to a data address are unknown", async () => {
    const { producer, run } = fixture();
    const data = await run("xrefs", { address: "0x3000" });
    expect(data.result).toEqual([]);
    expect(data.limitations).toContain("code references to it are unknown");
    expect(requests(producer, "bn_function_callers")).toEqual([]);
  });

  it("names the bound target as the only document without calling Binary Ninja", async () => {
    const { producer, run, target } = fixture();
    expect((await run("list_documents")).result).toEqual([target.path]);
    expect(producer.calls).toEqual([]);
  });

  it("reads across the 65536-byte request limit and stops at unmapped bytes", async () => {
    const { producer, run } = fixture();
    const read = await run("read_bytes", { address: "0x1000", length: 0x4010 });
    expect(read.result).toMatchObject({
      requested_bytes: 0x4010,
      returned_bytes: 0x4000,
      complete: false,
    });
    expect(requests(producer, "bn_memory_read")).toEqual([
      { address: "0x1000", length: 0x4010 },
    ]);
    producer.calls.length = 0;
    producer.overrideCall = (name, args) =>
      name === "bn_memory_read"
        ? {
            address: String(args.address),
            bytesRead: Number(args.length),
            hex: "00".repeat(Number(args.length)),
          }
        : undefined;
    const large = await run("read_bytes", {
      address: "0x1000",
      length: 70_000,
    });
    expect(large.result).toMatchObject({
      returned_bytes: 70_000,
      complete: true,
    });
    expect(requests(producer, "bn_memory_read")).toEqual([
      { address: "0x1000", length: 65_536 },
      { address: "0x11000", length: 4464 },
    ]);
  });
});

describe("Binary Ninja function observations", () => {
  it("resolves entries, rendered names, and unambiguous bare names", async () => {
    const { run } = fixture();
    for (const [procedure, address] of [
      ["0x1000", "0x1000"],
      ["0X2000", "0x2000"],
      ["main", "0x1000"],
      ["ns::helper(int32_t value)", "0x2000"],
      ["ns::helper", "0x2000"],
      ["helper", "0x2000"],
    ] as const)
      expect((await run("procedure_address", { procedure })).result).toBe(
        address,
      );
  });

  it("rejects an unknown, interior, or ambiguous procedure as caller input", async () => {
    const { producer, run } = fixture();
    producer.functions.push({
      address: "0x2800",
      name: "other::helper(int32_t value)",
      definition: "void(int32_t value)",
      ranges: "0x2800-0x2808 (8 bytes)",
      highest: "0x2807",
    });
    for (const [procedure, reason] of [
      ["missing", "No analyzed function is named missing"],
      ["0x1004", "No analyzed function starts at 0x1004"],
      ["helper", "2 analyzed functions match helper"],
    ] as const)
      await expect(
        run("procedure_pseudo_code", { procedure }),
      ).rejects.toMatchObject({
        _tag: "AnalysisInputError",
        issues: [
          { path: ["procedure"], message: expect.stringContaining(reason) },
        ],
      });
  });

  it("reports inclusive merged body ranges, stack records, and relationships", async () => {
    const { run } = fixture();
    expect((await run("procedure_info", { procedure: "main" })).result).toEqual(
      {
        name: "main",
        entrypoint: "0x1000",
        basicblock_count: 2,
        length: 24,
        signature: "int32_t(int32_t argc, char** argv)",
        locals: [
          {
            description: "int64_t var_8",
            provenance: "binary-ninja-stack-layout",
            name: "var_8",
            stack_displacement: "-8",
          },
          {
            description: "void* var_8_1",
            provenance: "binary-ninja-stack-layout",
            name: "var_8_1",
            stack_displacement: "-8",
          },
        ],
        classification: null,
        body: {
          available: true,
          provenance: "binary-ninja-function-ranges",
          ranges: [
            { start: "0x1000", end: "0x100f" },
            { start: "0x1018", end: "0x101f" },
          ],
          total_bytes: 24,
          span_bytes: 32,
          non_contiguous: true,
          contains_entry: true,
        },
      },
    );
    expect(
      (await run("procedure_callees", { procedure: "main" })).result,
    ).toEqual(["0x2000"]);
    expect(
      (await run("procedure_callers", { procedure: "helper" })).result,
    ).toEqual(["0x1000"]);
    expect(
      (await run("procedure_assembly", { procedure: "main" })).result,
    ).toBe("0x1000: push    rbp\n0x1018: retn     {__return_addr}");
    expect(
      (await run("procedure_pseudo_code", { procedure: "main" })).result,
    ).toBe("  main\n\n{\n    return 42;\n}");
  });

  it("merges touching printed ranges into maximal ones", async () => {
    const { producer, run } = fixture();
    producer.functions = [
      {
        address: "0x1000",
        name: "main",
        definition: "",
        ranges: "0x1010-0x1020 (16 bytes)<br>0x1000-0x1010 (16 bytes)",
        highest: "0x101f",
      },
    ];
    expect(
      (await run("procedure_info", { procedure: "0x1000" })).result,
    ).toMatchObject({
      signature: null,
      body: {
        ranges: [{ start: "0x1000", end: "0x101f" }],
        total_bytes: 32,
        span_bytes: 32,
        non_contiguous: false,
      },
    });
  });
});

describe("Binary Ninja function relationships", () => {
  it("keeps unresolved call sites and reference uncertainty explicit", async () => {
    const { run } = fixture();
    const outgoing = await run("procedure_references", {
      procedure: "main",
      direction: "outgoing",
    });
    expect(outgoing.result).toMatchObject({
      direction: "outgoing",
      reference_kinds_available: false,
      unresolved_calls: [
        {
          address: "0x1008",
          reason: "The target 0x4000 is not an analyzed function.",
        },
        {
          address: "0x100c",
          reason: expect.stringContaining("no target address"),
        },
      ],
      references: [
        {
          source_address: "0x1004",
          target_address: "0x2000",
          target_procedure: { address: "0x2000" },
          kind: { available: false },
        },
        {
          source_address: "0x1008",
          target_address: "0x4000",
          target_procedure: null,
        },
        { source_address: "0x1000", target_address: "0x0" },
        { source_address: "0x1000", target_address: "0x3000" },
      ],
    });
    const incoming = await run("procedure_references", {
      procedure: "helper",
      direction: "incoming",
    });
    // 0x2002 lies inside the function: its own control flow, not an incoming edge.
    expect(incoming.result).toMatchObject({
      references: [
        { source_address: "0x1004", source_procedure: { address: "0x1000" } },
        { source_address: "0x100e", target_address: "0x2000" },
      ],
    });
    expect(incoming.limitations).toContain("not the exact target");
  });

  it("builds a contract-valid dossier whose unsupported facets stay unknown", async () => {
    const { producer, run } = fixture();
    const { result } = await run("analyze_function", { procedure: "main" });
    const dossier = functionDossierSchema.parse(result);
    expect(dossier).toMatchObject({
      procedure: { address: "0x1000", name: "main", classification: null },
      pseudocode: "  main\n\n{\n    return 42;\n}",
      assembly: ["0x1000: push    rbp", "0x1018: retn     {__return_addr}"],
      comments: [{ address: "0x1000", kind: "comment", text: "entry note" }],
      callers: [],
      callees: [{ address: "0x2000", name: "ns::helper(int32_t value)" }],
      basic_blocks: [
        { start: "0x1000", end: "0x1010", successors: ["0x1018"] },
        { start: "0x1018", end: "0x1020", successors: [] },
      ],
      referenced_strings: [],
      referenced_names: [],
      native_api: null,
      native_value_flow: null,
    });
    expect(dossier.unresolved_calls).toHaveLength(2);
    expect(dossier.limitations.join(" ")).toContain(
      "unknown, not observed absence",
    );
    // One operation reads each call-site listing once.
    expect(requests(producer, "bn_function_callees")).toHaveLength(1);
    expect(requests(producer, "bn_function_callers")).toHaveLength(1);
  });

  it("follows pagination of large listings and retains no second copy of rows", async () => {
    const { producer, run } = fixture();
    const headers = [
      "function",
      "arch",
      "name",
      "platform",
      "lowestAddress",
      "highestAddress",
      "definition",
      "basicBlockCount",
      "exported",
      "autoDiscovered",
    ];
    const rows = Array.from({ length: 2300 }, (_, index) => [
      `0x${(0x10000 + index * 16).toString(16)}`,
      "x86_64",
      `sub_${String(index)}`,
      "linux-x86_64",
      "0x1",
      "0x2",
      "void()",
      "1",
      "false",
      "true",
    ]);
    producer.overrideCall = (name, args) =>
      name === "bn_function_list"
        ? binjaPage(name, args, { headers, rows })
        : undefined;
    const listed = await run("list_procedures");
    expect(listed.result).toHaveLength(2300);
    expect(requests(producer, "bn_function_list")).toHaveLength(3);
    expect(JSON.stringify(listed.runner.reader.raw)).not.toContain("sub_2299");
  });
});
