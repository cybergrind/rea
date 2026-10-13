import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { BinaryTarget } from "../../src/domain/binaryTargetTypes.js";
import { elf } from "../../src/domain/binaryTarget.fixture.js";
import type { JsonValue } from "../../src/domain/jsonValue.js";
import {
  BinjaToolError,
  type BinjaMcpConnection,
} from "../../src/binja/BinjaMcpConnection.js";
import { createTestTempDirectory } from "./temporaryDirectory.js";

/**
 * Binary Ninja MCP producer fixture.
 *
 * Reply shapes — front matter keys, complete column sets, code fences, JSON
 * documents and error envelopes — reproduce replies observed from
 * `binaryninja_ui_mcp` 0.1.0 on 2026-10-13. The contents are synthetic: the
 * databases open at capture time were private, so no captured row is stored
 * here. Unmodeled tools and arguments are rejected rather than answered.
 */

type Arguments = Readonly<Record<string, JsonValue>>;
type Row = readonly string[];

/** Bytes of the synthetic executable every fixture target contains. */
export const BINJA_TARGET_BYTES = elf(2, 1, 62);

/** A target description for tests that never read the file. */
export const binjaTarget = (path = "/fixtures/target.elf"): BinaryTarget => ({
  path,
  sha256: createHash("sha256").update(BINJA_TARGET_BYTES).digest("hex"),
  kind: "executable",
  format: "elf",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
});

/** Write the synthetic executable into a test-owned directory. */
export const materializeBinjaTarget = async (name = "target.elf") => {
  const root = await createTestTempDirectory("rea-binja-test-");
  const path = join(root, name);
  await writeFile(path, BINJA_TARGET_BYTES);
  return { root, target: binjaTarget(path) };
};

const frontMatter = (meta: Readonly<Record<string, JsonValue>>): string =>
  [
    "---",
    ...Object.entries(meta).map(
      ([key, value]) => `${key}: ${JSON.stringify(value)}`,
    ),
    "---",
    "",
  ].join("\n");

const table = (headers: Row, rows: readonly Row[]): string =>
  [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map(
      (row) => `| ${row.map((c) => c.replaceAll("|", "\\|")).join(" | ")} |`,
    ),
    "",
  ].join("\n");

const window = (args: Arguments, fallback: number) => ({
  offset: typeof args.offset === "number" ? args.offset : 0,
  limit: typeof args.limit === "number" ? args.limit : fallback,
});

/** Render one page of a listing as the Binary Ninja MCP prints it. */
export const binjaPage = (
  tool: string,
  args: Arguments,
  listing: {
    readonly headers: Row;
    readonly rows: readonly Row[];
    readonly lead?: Readonly<Record<string, JsonValue>>;
  },
): string => {
  const { offset, limit } = window(args, 100);
  const rows = listing.rows.slice(offset, offset + limit);
  const next =
    offset + rows.length < listing.rows.length ? offset + rows.length : null;
  return `${frontMatter({
    tool,
    ...listing.lead,
    offset,
    limit,
    count: rows.length,
    total: listing.rows.length,
    nextOffset: next,
    truncated: next !== null,
  })}\n${table(listing.headers, rows)}`;
};

/** Render one page of a function's code block as the Binary Ninja MCP prints it. */
export const binjaBlock = (
  tool: string,
  args: Arguments,
  code: {
    readonly lead: Readonly<Record<string, JsonValue>>;
    readonly fence: string;
    readonly lines: readonly string[];
    readonly trail?: Readonly<Record<string, JsonValue>>;
  },
): string => {
  const { offset, limit } = window(args, 1000);
  const page = code.lines.slice(offset, offset + limit);
  const next =
    offset + page.length < code.lines.length ? offset + page.length : null;
  return `${frontMatter({
    tool,
    ...code.lead,
    offset,
    limit,
    count: page.length,
    total: code.lines.length,
    nextOffset: next,
    truncated: next !== null,
    ...code.trail,
  })}\n\`\`\`\`${code.fence}\n${page.join("\n")}\n\`\`\`\`\n`;
};

export interface FixtureFunction {
  readonly address: string;
  readonly name: string;
  readonly definition: string;
  /** Half-open ranges as printed, `<br>`-separated. */
  readonly ranges: string;
  readonly highest: string;
}

const MAIN: FixtureFunction = {
  address: "0x1000",
  name: "main",
  definition: "int32_t(int32_t argc, char** argv)",
  ranges: "0x1000-0x1010 (16 bytes)<br>0x1018-0x1020 (8 bytes)",
  highest: "0x101f",
};
const HELPER: FixtureFunction = {
  address: "0x2000",
  name: "ns::helper(int32_t value)",
  definition: "void(int32_t value)",
  ranges: "0x2000-0x2008 (8 bytes)",
  highest: "0x2007",
};
const ARCH = "x86_64";
const PLATFORM = "linux-x86_64";
const functionRef = (fn: FixtureFunction) =>
  `${fn.name} (${fn.address} (${ARCH}))`;
const functionLead = (fn: FixtureFunction) => ({
  function: fn.address,
  arch: ARCH,
  name: fn.name,
  platform: PLATFORM,
});

/** Complete column sets of the listings, in the order Binary Ninja prints them. */
export const BINJA_LISTING_HEADERS = {
  views: [
    "binaryView",
    "openItem",
    "viewType",
    "longName",
    "created",
    "active",
    "available",
    "recommended",
    "architecture",
    "platform",
    "addressSize",
    "start",
    "end",
    "entryPoint",
    "modified",
    "analysisModified",
  ],
  items: [
    "openItem",
    "kind",
    "displayName",
    "path",
    "projectPath",
    "sessionId",
    "modified",
    "analysisModified",
    "saveable",
    "databaseBacked",
    "validSavePath",
  ],
  segments: [
    "segment",
    "start",
    "end",
    "length",
    "dataOffset",
    "dataLength",
    "dataEnd",
    "flags",
    "readable",
    "writable",
    "executable",
    "containsData",
    "containsCode",
    "denyWrite",
    "denyExecute",
    "autoDefined",
  ],
  sections: [
    "section",
    "start",
    "end",
    "length",
    "typeName",
    "semantics",
    "alignment",
    "entrySize",
    "linkedSection",
    "infoSection",
    "infoData",
    "autoDefined",
  ],
  functions: [
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
  ],
  strings: [
    "string",
    "type",
    "length",
    "previewEscaped",
    "previewHex",
    "previewTruncated",
  ],
  symbols: [
    "symbol",
    "name",
    "type",
    "namespace",
    "ordinal",
    "binding",
    "fullName",
    "autoDefined",
  ],
} as const;

/** Arguments each modeled tool accepts; anything else is rejected. */
const ACCEPTED: Readonly<Record<string, readonly string[]>> = {
  bn_binary_view_list: ["offset", "limit"],
  bn_open_item_list: ["offset", "limit"],
  bn_analysis_status: [],
  bn_segment_list: ["offset", "limit"],
  bn_section_list: ["offset", "limit"],
  bn_function_list: ["offset", "limit", "query", "address"],
  bn_string_list: ["offset", "limit", "query", "address", "previewBytes"],
  bn_symbol_list: ["offset", "limit"],
  bn_symbol_list_at: ["address"],
  bn_data_xrefs_to: ["address", "offset", "limit"],
  bn_data_at: ["address"],
  bn_memory_read: ["address", "length"],
  bn_comment_get: ["comment"],
  bn_function_info: ["function"],
  bn_function_decompile: ["function", "offset", "limit"],
  bn_function_disassembly: ["function", "offset", "limit"],
  bn_function_callers: ["function", "offset", "limit"],
  bn_function_callees: ["function", "offset", "limit"],
  bn_function_xrefs_to: ["function", "offset", "limit"],
  bn_function_xrefs_from: ["function", "offset", "limit"],
  bn_function_basic_blocks: ["function", "offset", "limit"],
  bn_function_stack_layout: ["function", "offset", "limit"],
};

export interface FixtureString {
  readonly address: string;
  readonly type: string;
  /** Complete object bytes; the listing previews at most `previewBytes`. */
  readonly bytes: Buffer;
  readonly display: string;
}

/** Stateful producer fixture at the real connection seam; no module mocking. */
export class BinjaProducerFixture implements BinjaMcpConnection {
  readonly calls: { name: string; args: Arguments }[] = [];
  connects = 0;
  closes = 0;
  inFlight = 0;
  maxInFlight = 0;
  tools: readonly string[] = Object.keys(ACCEPTED);
  /** Handles of the views the producer reports as active. */
  activeViews: string[] = ["view_1"];
  analysisState = "IdleState";
  itemPath: string;
  /** Size of the raw view, or null when the producer lists no raw view. */
  rawBytes: number | null = BINJA_TARGET_BYTES.length;
  header = Buffer.from(BINJA_TARGET_BYTES);
  /** File offset the first segment maps; nonzero leaves offset zero unmapped. */
  firstSegmentOffset = 0;
  imageBase = "0x1000";
  functions: FixtureFunction[] = [MAIN, HELPER];
  longString = `${"x".repeat(300)}needle-in-the-tail`;
  strings: FixtureString[];
  beforeCall: ((name: string, args: Arguments) => Promise<void>) | undefined;
  overrideCall:
    | ((name: string, args: Arguments) => JsonValue | undefined)
    | undefined;

  constructor(readonly target: BinaryTarget) {
    this.itemPath = `${target.path}.bndb`;
    this.strings = [
      {
        address: "0x3000",
        type: "AsciiString",
        bytes: Buffer.from("a.b\nC"),
        display: "a.b\\nC",
      },
      {
        address: "0x3100",
        type: "AsciiString",
        bytes: Buffer.from(this.longString),
        display: this.longString,
      },
      {
        address: "0x3400",
        type: "Utf16String",
        bytes: Buffer.from("hi", "utf16le"),
        display: "hi",
      },
    ];
  }

  async connect() {
    this.connects += 1;
    return this.tools;
  }
  serverInfo() {
    return { name: "binaryninja_ui_mcp", version: "0.1.0" };
  }
  async close() {
    this.closes += 1;
  }

  async call(name: string, args: Arguments): Promise<JsonValue> {
    this.calls.push({ name, args: structuredClone(args) });
    const accepted = ACCEPTED[name];
    if (accepted === undefined)
      throw new Error(`Unmodeled Binary Ninja MCP tool: ${name}`);
    const unknown = Object.keys(args).filter((key) => !accepted.includes(key));
    if (unknown.length > 0)
      throw new Error(`Unmodeled ${name} argument(s): ${unknown.join(", ")}`);
    if (typeof args.limit === "number" && args.limit > 1000)
      throw new BinjaToolError(name, "invalid_params", "limit exceeds 1000");
    this.inFlight += 1;
    this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
    try {
      await this.beforeCall?.(name, args);
      // A real server yields between request and reply; overlap must show here.
      await new Promise((resolve) => setImmediate(resolve));
      return (
        this.overrideCall?.(name, args) ??
        this.session(name, args) ??
        this.layout(name, args) ??
        this.listing(name, args) ??
        this.scoped(name, args)
      );
    } finally {
      this.inFlight -= 1;
    }
  }

  private fn(args: Arguments): FixtureFunction {
    const found = this.functions.find(
      ({ address }) => address === args.function,
    );
    if (found === undefined)
      throw new BinjaToolError(
        "bn_function_info",
        "function_not_found",
        "No matching function was found",
      );
    return found;
  }

  private memory(args: Arguments): JsonValue {
    const address = Number(args.address);
    const length = Number(args.length);
    const image = Buffer.alloc(0x4000);
    this.header.copy(image);
    for (const { address: at, bytes } of this.strings)
      bytes.copy(image, Number(at) - 0x1000);
    const start = address - 0x1000;
    const bytes =
      start < 0 || start >= image.length
        ? Buffer.alloc(0)
        : image.subarray(start, start + length);
    return {
      address: `0x${address.toString(16)}`,
      requestedLength: `0x${length.toString(16)}`,
      bytesRead: bytes.length,
      hex: bytes.toString("hex"),
      base64: `${bytes.toString("base64")}\n`,
      warnings:
        bytes.length === length
          ? []
          : [
              {
                code: "partial_read",
                message: "Binary Ninja returned fewer bytes than requested",
              },
            ],
    };
  }

  private session(name: string, args: Arguments): JsonValue | undefined {
    const active = (view: string) => String(this.activeViews.includes(view));
    switch (name) {
      case "bn_analysis_status":
        return {
          analysis: {
            state: this.analysisState,
            stateValue: 2,
            progress: {
              state: this.analysisState,
              stateValue: 2,
              count: 0,
              total: 0,
            },
            info: {
              state: this.analysisState,
              stateValue: 2,
              analysisTime: 0,
              active: [],
            },
          },
          warnings: [],
        };
      case "bn_binary_view_list":
        return binjaPage(name, args, {
          headers: BINJA_LISTING_HEADERS.views,
          rows: [
            [
              "view_1",
              "item_1",
              "ELF",
              "ELF",
              "true",
              active("view_1"),
              "true",
              "true",
              ARCH,
              PLATFORM,
              "8",
              this.imageBase,
              "0x5000",
              "0x1000",
              "false",
              "false",
            ],
            ...(this.rawBytes === null
              ? []
              : [
                  [
                    "view_2",
                    "item_1",
                    "Raw",
                    "Raw",
                    "true",
                    active("view_2"),
                    "true",
                    "false",
                    "",
                    "",
                    "4",
                    "0x0",
                    `0x${this.rawBytes.toString(16)}`,
                    "0x0",
                    "false",
                    "false",
                  ],
                ]),
          ],
        });
      case "bn_open_item_list":
        return binjaPage(name, args, {
          headers: BINJA_LISTING_HEADERS.items,
          rows: [
            [
              "item_1",
              "database",
              "target.elf.bndb",
              this.itemPath,
              "",
              "978945138564900512",
              "false",
              "false",
              "true",
              "true",
              "true",
            ],
          ],
        });
      case "bn_memory_read":
        return this.memory(args);
      case "bn_comment_get":
        return {
          comment: args.comment ?? null,
          text: args.comment === "0x1000" ? "entry note" : "",
          warnings: [],
        };
      default:
        return undefined;
    }
  }

  private layout(name: string, args: Arguments): JsonValue | undefined {
    switch (name) {
      case "bn_segment_list":
        return binjaPage(name, args, {
          headers: BINJA_LISTING_HEADERS.segments,
          rows: [
            [
              "0x1000",
              "0x1000",
              "0x3000",
              "0x2000",
              `0x${this.firstSegmentOffset.toString(16)}`,
              "0x2000",
              "0x3000",
              "SegmentReadable, SegmentExecutable, SegmentContainsCode",
              "true",
              "false",
              "true",
              "false",
              "true",
              "false",
              "false",
              "true",
            ],
            [
              "0x3000",
              "0x3000",
              "0x5000",
              "0x2000",
              "0x2000",
              "0x800",
              "0x3800",
              "SegmentReadable, SegmentWritable, SegmentContainsData",
              "true",
              "true",
              "false",
              "true",
              "false",
              "false",
              "false",
              "true",
            ],
          ],
        });
      case "bn_section_list":
        return binjaPage(name, args, {
          headers: BINJA_LISTING_HEADERS.sections,
          rows: [
            [
              ".text",
              "0x1000",
              "0x3000",
              "0x2000",
              "",
              "ReadOnlyCodeSectionSemantics",
              "0x1",
              "0x0",
              "",
              "",
              "0x0",
              "true",
            ],
            [
              ".data",
              "0x3000",
              "0x5000",
              "0x2000",
              "",
              "ReadWriteDataSectionSemantics",
              "0x1",
              "0x0",
              "",
              "",
              "0x0",
              "true",
            ],
          ],
        });
      default:
        return undefined;
    }
  }

  private stringRows(args: Arguments): Row[] {
    const preview =
      typeof args.previewBytes === "number" ? args.previewBytes : 64;
    const query =
      typeof args.query === "string" ? args.query.toLowerCase() : undefined;
    return this.strings
      .filter(
        ({ address, display }) =>
          (args.address === undefined || args.address === address) &&
          (query === undefined || display.toLowerCase().includes(query)),
      )
      .map(({ address, type, bytes, display }) => [
        address,
        type,
        `0x${bytes.length.toString(16)}`,
        bytes.length > preview ? display.slice(0, preview) : display,
        bytes.subarray(0, preview).toString("hex"),
        String(bytes.length > preview),
      ]);
  }

  private listing(name: string, args: Arguments): JsonValue | undefined {
    const filter = {
      ...(typeof args.query === "string" ? { query: args.query } : {}),
      ...(typeof args.address === "string" ? { start: args.address } : {}),
    };
    switch (name) {
      case "bn_function_list":
        return binjaPage(name, args, {
          headers: BINJA_LISTING_HEADERS.functions,
          lead: filter,
          rows: this.functions
            .filter(
              (fn) =>
                (typeof args.query !== "string" ||
                  fn.name.toLowerCase().includes(args.query.toLowerCase())) &&
                (args.address === undefined || args.address === fn.address),
            )
            .map((fn) => [
              fn.address,
              ARCH,
              fn.name,
              PLATFORM,
              fn.address,
              fn.highest,
              fn.definition,
              "2",
              "false",
              "true",
            ]),
        });
      case "bn_string_list":
        return binjaPage(name, args, {
          headers: BINJA_LISTING_HEADERS.strings,
          lead: {
            ...filter,
            previewBytes:
              typeof args.previewBytes === "number" ? args.previewBytes : 64,
          },
          rows: this.stringRows(args),
        });
      case "bn_symbol_list":
        return binjaPage(name, args, {
          headers: BINJA_LISTING_HEADERS.symbols,
          rows: this.symbols(),
        });
      case "bn_symbol_list_at": {
        const rows = this.symbols().filter(([at]) => at === args.address);
        return `${frontMatter({ tool: name, address: args.address ?? null, count: rows.length })}\n${table(BINJA_LISTING_HEADERS.symbols, rows)}`;
      }
      case "bn_data_xrefs_to":
        return binjaPage(name, args, {
          headers: ["Source", "Source Data Variable", "Source Definition"],
          lead: { address: args.address ?? null },
          rows:
            args.address === "0x2000" ? [["0x3800", "0x3800", "void*"]] : [],
        });
      case "bn_data_at": {
        const at = Number(args.address);
        return {
          address: args.address ?? null,
          dataVariable: null,
          exactDataVariable: false,
          comment: "",
          symbols: [],
          functions: this.functions
            .filter(
              ({ address, highest }) =>
                at >= Number(address) && at <= Number(highest),
            )
            .map(({ address, name: fn }) => ({
              function: address,
              arch: ARCH,
              start: address,
              architecture: ARCH,
              platform: PLATFORM,
              name: fn,
            })),
          warnings: [],
        };
      }
      default:
        return undefined;
    }
  }

  private symbols(): Row[] {
    const symbol = (at: string, name: string, type: string, full: string) => [
      at,
      name,
      type,
      "BNINTERNALNAMESPACE",
      "0",
      "NoBinding",
      full,
      "true",
    ];
    return [
      symbol("0x1000", "main", "FunctionSymbol", "main"),
      symbol("0x2000", "helper", "FunctionSymbol", "ns::helper"),
      symbol("0x3000", "message", "DataSymbol", "message"),
    ];
  }

  private scoped(name: string, args: Arguments): JsonValue {
    const fn = this.fn(args);
    const lead = functionLead(fn);
    const rows = (headers: Row, all: readonly Row[]) =>
      binjaPage(name, args, { headers, rows: all, lead });
    const isMain = fn.address === MAIN.address;
    const isHelper = fn.address === HELPER.address;
    switch (name) {
      case "bn_function_info":
        return `${frontMatter({ tool: name, ...lead })}\n## Function\n\n${table(
          ["Field", "Value"],
          [
            ["Function", `${fn.address} (${ARCH})`],
            ["Name", fn.name],
            ["Start", fn.address],
            ["Lowest Address", fn.address],
            ["Highest Address", fn.highest],
            ["Architecture", ARCH],
            ["Platform", PLATFORM],
            ["Definition", fn.definition],
            ["Exported", "false"],
            ["Auto Discovered", "false"],
            ["Has User Annotations", "false"],
            ["Needs Update", "false"],
            ["Analysis Skipped", "false"],
            ["Analysis Skip Reason", "NoSkipReason"],
            ["Basic Blocks", "2"],
            ["Ranges", fn.ranges],
          ],
        )}\n## Basic Blocks\n\n${table(
          ["Index", "Range", "Incoming", "Outgoing"],
          [["0", "0x1000-0x1010 (16 bytes)", "0", "1"]],
        )}`;
      case "bn_function_decompile":
        return binjaBlock(name, args, {
          lead: { ...lead, language: "Pseudo C" },
          fence: "bn-pseudoc",
          lines: [`  ${fn.name}`, "", "{", "    return 42;", "}"],
          trail: { needsUpdate: false },
        });
      case "bn_function_disassembly":
        return binjaBlock(name, args, {
          lead,
          fence: "asm",
          lines: [
            `  ${fn.name}`,
            "",
            `${fn.address}  push    rbp`,
            "",
            "0x1018  retn     {__return_addr}",
          ],
        });
      case "bn_function_callers":
        return rows(
          ["Callsite", "Architecture", "Caller Function"],
          isHelper ? [["0x1004", ARCH, functionRef(MAIN)]] : [],
        );
      case "bn_function_callees":
        return rows(
          ["Callsite", "Architecture", "Callee Address", "Callee Functions"],
          isMain
            ? [
                ["0x1004", ARCH, "0x2000", functionRef(HELPER)],
                ["0x1008", ARCH, "0x4000", ""],
                ["0x100c", ARCH, "", ""],
              ]
            : [],
        );
      case "bn_function_xrefs_to":
        return rows(
          ["Source", "Architecture", "Source Function", "Target Range"],
          isHelper
            ? [
                ["0x1004", ARCH, functionRef(MAIN), fn.ranges],
                ["0x100e", ARCH, functionRef(MAIN), fn.ranges],
                ["0x2002", ARCH, functionRef(HELPER), fn.ranges],
              ]
            : [],
        );
      case "bn_function_xrefs_from":
        return rows(
          ["Source Range", "Target", "Target Functions"],
          isMain
            ? [
                ["0x1000-0x1010 (16 bytes)", "0x0", ""],
                ["0x1000-0x1010 (16 bytes)", "0x2000", functionRef(HELPER)],
                ["0x1000-0x1010 (16 bytes)", "0x3000", ""],
              ]
            : [],
        );
      case "bn_function_basic_blocks":
        return rows(
          ["Index", "Range", "Flags", "Incoming Edges", "Outgoing Edges"],
          [
            [
              "0",
              "0x1000-0x1010 (16 bytes)",
              "can-exit",
              "",
              "TrueBranch #1 0x1018-0x1020 (8 bytes)<br>FalseBranch #1 0x1018-0x1020 (8 bytes) fallthrough",
            ],
            [
              "1",
              "0x1018-0x1020 (8 bytes)",
              "can-exit",
              "TrueBranch #0 0x1000-0x1010 (16 bytes)<br>FalseBranch #0 0x1000-0x1010 (16 bytes) fallthrough",
              "",
            ],
          ],
        );
      case "bn_function_stack_layout":
        return rows(
          [
            "Offset",
            "Offset Hex",
            "Variable",
            "Definition",
            "Confidence",
            "Auto Defined",
          ],
          [
            ["-8", "-0x8", "var_8", "int64_t", "0", "true"],
            ["-8", "-0x8", "var_8_1", "void*", "255", "true"],
          ],
        );
      default:
        throw new Error(`Unmodeled Binary Ninja MCP tool: ${name}`);
    }
  }
}

/** Answer only the exact scripted requests; any other call fails the test. */
export const scriptedBinjaConnection = (
  script: ReadonlyMap<string, JsonValue | Error>,
): BinjaMcpConnection & { readonly calls: string[] } => {
  const calls: string[] = [];
  return {
    calls,
    async connect() {
      return [];
    },
    async call(name, args) {
      const key = binjaRequest(name, args);
      calls.push(key);
      const reply = script.get(key);
      if (reply === undefined)
        throw new Error(`Unscripted Binary Ninja MCP request: ${key}`);
      if (reply instanceof Error) throw reply;
      return reply;
    },
    serverInfo: () => null,
    async close() {},
  };
};

/** The exact-match key of one scripted request. */
export const binjaRequest = (name: string, args: Arguments): string =>
  `${name} ${JSON.stringify(args)}`;
