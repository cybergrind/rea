import { z } from "zod";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";

/** Normalize a Binary Ninja hexadecimal coordinate without passing through a JavaScript number. */
export const binjaAddressSchema = z
  .string()
  .regex(/^(?:0x)?[0-9a-f]+$/iu)
  .transform(
    (value) =>
      `0x${BigInt(/^0x/iu.test(value) ? value : `0x${value}`).toString(16)}`,
  );

const cellBoolean = z.enum(["true", "false"]).transform((v) => v === "true");
const cellCount = z
  .string()
  .regex(/^(?:0x[0-9a-f]+|\d+)$/iu)
  .transform(Number)
  .pipe(z.number().int().min(0).max(Number.MAX_SAFE_INTEGER));
const cellSigned = z.string().regex(/^-?\d+$/u);

type Scalar = string | number | boolean | null;

/** One markdown table of a reply, with the `## heading` that introduced it. */
export interface BinjaTable {
  readonly heading: string | null;
  readonly headers: readonly string[];
  readonly rows: readonly Readonly<Record<string, string>>[];
}

/** A parsed text reply: front matter, then tables or one fenced block. */
export interface BinjaTextReply {
  readonly meta: Readonly<Record<string, Scalar>>;
  readonly tables: readonly BinjaTable[];
  readonly block: string | null;
}

const malformed = (reason: string): AnalysisProtocolError =>
  new AnalysisProtocolError(
    `Binary Ninja MCP returned an unsupported text reply: ${reason}`,
  );

const scalar = (raw: string): Scalar => {
  const text = raw.trim();
  try {
    const value: unknown = JSON.parse(text);
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    )
      return value;
  } catch {
    // Front matter values are JSON scalars; anything else stays literal text.
  }
  return text;
};

const splitRow = (line: string): string[] => {
  let text = line.trim();
  if (text.startsWith("|")) text = text.slice(1);
  if (text.endsWith("|") && !text.endsWith("\\|")) text = text.slice(0, -1);
  return text
    .split(/(?<!\\)\|/u)
    .map((cell) => cell.trim().replaceAll("\\|", "|"));
};

const SEPARATOR = /^\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|?\s*$/u;
const FENCE = /^(`{3,})\S*\s*$/u;

const parseFrontMatter = (
  lines: readonly string[],
): { meta: Record<string, Scalar>; next: number } => {
  if (lines[0]?.trim() !== "---") throw malformed("missing front matter");
  const meta: Record<string, Scalar> = {};
  for (let index = 1; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (line.trim() === "---") return { meta, next: index + 1 };
    if (line.trim() === "") continue;
    const separator = line.indexOf(":");
    if (separator < 0) throw malformed("malformed front matter line");
    meta[line.slice(0, separator).trim()] = scalar(line.slice(separator + 1));
  }
  throw malformed("unterminated front matter");
};

const parseFence = (
  lines: readonly string[],
  start: number,
  fence: string,
): string => {
  const body: string[] = [];
  for (let index = start; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (line.trim() === fence) return body.join("\n");
    body.push(line);
  }
  // A missing closing fence is a cut-off reply, never a complete observation.
  throw malformed("unterminated code block");
};

/** Parse the YAML-like front matter and markdown body every text tool returns. */
export const parseBinjaText = (text: string): BinjaTextReply => {
  const lines = text.split(/\r?\n/u);
  const { meta, next } = parseFrontMatter(lines);
  const tables: BinjaTable[] = [];
  let heading: string | null = null;
  let table: { headers: string[]; rows: Record<string, string>[] } | null =
    null;
  const flush = () => {
    if (table !== null) tables.push({ heading, ...table });
    table = null;
  };
  for (let index = next; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const fence = FENCE.exec(line);
    if (fence !== null && table === null && tables.length === 0)
      return {
        meta,
        tables: [],
        block: parseFence(lines, index + 1, fence[1] ?? ""),
      };
    if (line.trim() === "") {
      flush();
      continue;
    }
    if (line.startsWith("## ")) {
      flush();
      heading = line.slice(3).trim();
      continue;
    }
    if (!line.trimStart().startsWith("|"))
      throw malformed("unexpected body line outside a table");
    if (table === null) {
      table = { headers: splitRow(line), rows: [] };
      continue;
    }
    if (SEPARATOR.test(line)) continue;
    const cells = splitRow(line);
    if (cells.length !== table.headers.length)
      throw malformed(
        `a table row has ${String(cells.length)} cells where ${String(table.headers.length)} were declared`,
      );
    table.rows.push(
      Object.fromEntries(
        table.headers.map((header, column) => [header, cells[column] ?? ""]),
      ),
    );
  }
  flush();
  return { meta, tables, block: null };
};

/** Pagination facts every listing reports; a page either finishes or advances. */
export const binjaPageSchema = z.looseObject({
  offset: z.number().int().min(0),
  count: z.number().int().min(0),
  total: z.number().int().min(0),
  nextOffset: z.number().int().min(0).nullable(),
  truncated: z.boolean(),
});

/** The function a function-scoped reply declares it describes. */
export const binjaFunctionMetaSchema = z.looseObject({
  function: binjaAddressSchema,
  name: z.string().min(1),
});

export const binjaFunctionRowSchema = z.looseObject({
  function: binjaAddressSchema,
  name: z.string().min(1),
  lowestAddress: binjaAddressSchema,
  highestAddress: binjaAddressSchema,
  definition: z.string(),
  basicBlockCount: cellCount,
});

export const binjaStringRowSchema = z.looseObject({
  string: binjaAddressSchema,
  type: z.string().min(1),
  length: cellCount,
  previewEscaped: z.string(),
  previewHex: z.string().regex(/^(?:[0-9a-f]{2})*$/iu),
  previewTruncated: cellBoolean,
});
export type BinjaStringRow = z.infer<typeof binjaStringRowSchema>;

export const binjaSymbolRowSchema = z.looseObject({
  symbol: binjaAddressSchema,
  name: z.string(),
  type: z.string(),
  fullName: z.string(),
});

export const binjaViewRowSchema = z.looseObject({
  binaryView: z.string().min(1),
  openItem: z.string().min(1),
  viewType: z.string(),
  active: cellBoolean,
  // An available but uncreated view candidate has no address range yet.
  start: z.string(),
  end: z.string(),
  architecture: z.string(),
  platform: z.string(),
});
export type BinjaViewRow = z.infer<typeof binjaViewRowSchema>;

export const binjaOpenItemRowSchema = z.looseObject({
  openItem: z.string().min(1),
  kind: z.string(),
  path: z.string(),
});

export const binjaSegmentRowSchema = z.looseObject({
  start: binjaAddressSchema,
  end: binjaAddressSchema,
  dataOffset: cellCount,
  dataLength: cellCount,
  readable: cellBoolean,
  writable: cellBoolean,
  executable: cellBoolean,
});
export type BinjaSegmentRow = z.infer<typeof binjaSegmentRowSchema>;

export const binjaSectionRowSchema = z.looseObject({
  section: z.string(),
  start: binjaAddressSchema,
  end: binjaAddressSchema,
  semantics: z.string(),
});

export const binjaCallerRowSchema = z.looseObject({
  Callsite: binjaAddressSchema,
  "Caller Function": z.string(),
});
export const binjaCalleeRowSchema = z.looseObject({
  Callsite: binjaAddressSchema,
  "Callee Address": z.string(),
  "Callee Functions": z.string(),
});
export const binjaIncomingReferenceRowSchema = z.looseObject({
  Source: binjaAddressSchema,
  "Source Function": z.string(),
});
export const binjaOutgoingReferenceRowSchema = z.looseObject({
  "Source Range": z.string(),
  Target: binjaAddressSchema,
  "Target Functions": z.string(),
});
export const binjaDataReferenceRowSchema = z.looseObject({
  Source: binjaAddressSchema,
});
export const binjaBasicBlockRowSchema = z.looseObject({
  Range: z.string(),
  "Outgoing Edges": z.string(),
});
export const binjaStackRowSchema = z.looseObject({
  Offset: cellSigned,
  Variable: z.string(),
  Definition: z.string(),
});

/** Structured replies of the tools that answer with one JSON document. */
export const binjaMemoryReadSchema = z.looseObject({
  address: binjaAddressSchema,
  bytesRead: z.number().int().min(0),
  hex: z.string().regex(/^(?:[0-9a-f]{2})*$/iu),
});
export const binjaCommentSchema = z.looseObject({ text: z.string() });
export const binjaDataAtSchema = z.looseObject({
  address: binjaAddressSchema,
  functions: z.array(
    z.looseObject({ start: binjaAddressSchema, name: z.string().min(1) }),
  ),
});
export const binjaAnalysisStatusSchema = z.looseObject({
  analysis: z.looseObject({
    state: z.string().min(1),
    progress: z
      .looseObject({
        count: z.number().int().min(0).nullish(),
        total: z.number().int().min(0).nullish(),
      })
      .nullish(),
  }),
});
export const binjaToolFailureSchema = z.looseObject({
  errorCode: z.string(),
  errorMessage: z.string(),
});

const FUNCTION_REFERENCE = /(.*?)\s*\((0x[0-9a-f]+) \([^()]*\)\)(?:,\s*|$)/giu;

/** Decode a `NAME (0xADDR (arch)), …` cell; an empty cell names no function. */
export const parseBinjaFunctionReferences = (
  cell: string,
): { address: string; name: string }[] => {
  if (cell.trim() === "") return [];
  const found = [...cell.matchAll(FUNCTION_REFERENCE)].map((match) => ({
    address: binjaAddressSchema.parse(match[2]),
    name: (match[1] ?? "").trim(),
  }));
  if (found.length === 0)
    throw malformed("a function cell does not name `NAME (0xADDR (arch))`");
  return found;
};

const RANGE = /^(0x[0-9a-f]+)-(0x[0-9a-f]+) \((\d+) bytes\)/iu;

/** A half-open `[start, end)` byte range as Binary Ninja prints it. */
export interface BinjaRange {
  readonly start: bigint;
  readonly end: bigint;
}

/** Decode `0xSTART-0xEND (N bytes)`; the printed end is exclusive. */
export const parseBinjaRange = (text: string): BinjaRange => {
  const match = RANGE.exec(text.trim());
  if (match === null) throw malformed("a range cell is not 0xSTART-0xEND");
  const start = BigInt(match[1] ?? "0x0");
  const end = BigInt(match[2] ?? "0x0");
  if (end <= start || end - start !== BigInt(match[3] ?? "0"))
    throw malformed("a range cell disagrees with its own byte count");
  return { start, end };
};

/** Split a multi-valued cell; Binary Ninja separates values with `<br>`. */
export const splitBinjaCell = (cell: string): string[] =>
  cell
    .split(/<br\s*\/?>/iu)
    .map((part) => part.trim())
    .filter((part) => part !== "");

/** Render a bigint coordinate in the canonical lowercase form. */
export const binjaHex = (value: bigint): string => `0x${value.toString(16)}`;
