import { z } from "zod";
import { analysisSearchInput } from "../contracts/analysisSearchContract.js";
import {
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  binjaCommentSchema,
  binjaDataAtSchema,
  binjaDataReferenceRowSchema,
  binjaFunctionRowSchema,
  binjaHex,
  binjaMemoryReadSchema,
  binjaSectionRowSchema,
  binjaSegmentRowSchema,
  binjaStringRowSchema,
  binjaSymbolRowSchema,
  type BinjaSegmentRow,
  type BinjaStringRow,
} from "./BinjaProtocolValues.js";
import {
  binjaProcedureIdentity,
  type BinjaFunctionOperations,
} from "./BinjaFunctionOperations.js";
import type { BinjaToolReader } from "./BinjaToolReader.js";

/** bn_string_list returns at most this many preview bytes per object. */
const STRING_PREVIEW_BYTES = 256;
/** bn_memory_read returns at most this many bytes per request. */
const MEMORY_READ_BYTES = 65_536;

const SEGMENT_SOURCE = "binary-ninja-segment";
const front = { retain: "front-matter", exhaustive: true } as const;
const searchSchema = z.object(analysisSearchInput);
type Search = z.infer<typeof searchSchema>;

/** A literal Binary Ninja's own substring filter can preselect without loss of text. */
const filterable = (query: Search): boolean =>
  query.mode === "literal" &&
  /^[\x20-\x5b\x5d-\x7b\x7d\x7e]+$/u.test(query.pattern);

const matcher = (query: Search): ((value: string) => boolean) => {
  if (query.mode === "regex") {
    const regex = new RegExp(query.pattern, query.case_sensitive ? "u" : "iu");
    return (value) => regex.test(value);
  }
  const needle = query.case_sensitive
    ? query.pattern
    : query.pattern.toLowerCase();
  return (value) =>
    (query.case_sensitive ? value : value.toLowerCase()).includes(needle);
};

const decodeUtf32 = (bytes: Buffer): string => {
  if (bytes.length % 4 !== 0) throw new RangeError("odd UTF-32 length");
  let text = "";
  for (let offset = 0; offset < bytes.length; offset += 4) {
    const point = bytes.readUInt32LE(offset);
    // A surrogate is not a scalar value; fromCodePoint rejects the rest.
    if (point >= 0xd800 && point <= 0xdfff) throw new RangeError("surrogate");
    text += String.fromCodePoint(point);
  }
  return text;
};

/** Decode typed string bytes; a failure keeps Binary Ninja's own display text. */
const decodeString = (type: string, hex: string, display: string) => {
  const bytes = Buffer.from(hex, "hex");
  try {
    const value = /utf-?32/iu.test(type)
      ? decodeUtf32(bytes)
      : new TextDecoder(/utf-?16/iu.test(type) ? "utf-16le" : "utf-8", {
          fatal: true,
        }).decode(bytes);
    return value === display ? { value } : { value, provider_value: display };
  } catch {
    return {
      value: display,
      decoding: {
        available: false,
        reason: `The ${type} bytes do not decode; the value is Binary Ninja's escaped display text.`,
      } as const,
    };
  }
};

/** Whole-database listings and address-scoped facts of an attached Binary Ninja. */
export class BinjaInventoryOperations {
  constructor(
    private readonly reader: BinjaToolReader,
    private readonly functions: BinjaFunctionOperations,
  ) {}

  async procedures(query?: Search): Promise<JsonValue> {
    const narrowed = query !== undefined && filterable(query);
    const rows = await this.reader.rows(
      "bn_function_list",
      narrowed ? { query: query.pattern } : {},
      binjaFunctionRowSchema,
      front,
    );
    const items = rows.map((row) => ({
      address: row.function,
      value: row.name,
    }));
    if (query === undefined) return items;
    if (narrowed)
      this.reader.limit(
        "Candidates were preselected by Binary Ninja's substring filter over function symbol names; a literal that occurs only in rendered parameter text is not found. Regex mode walks every rendered name.",
      );
    const matches = matcher(query);
    return items.filter(({ value }) => matches(value));
  }

  async #stringValue(row: BinjaStringRow, complete: boolean) {
    let hex = row.previewHex;
    let cut = row.previewTruncated;
    if (cut && complete && row.length <= MEMORY_READ_BYTES) {
      const read = await this.reader.structured(
        "bn_memory_read",
        { address: row.string, length: row.length },
        binjaMemoryReadSchema,
      );
      if (read.bytesRead === row.length) {
        hex = read.hex;
        cut = false;
      }
    }
    return {
      cut,
      item: {
        address: row.string,
        ...decodeString(row.type, hex, row.previewEscaped),
      },
    };
  }

  async strings(input: { address?: string; query?: Search }) {
    const { address, query } = input;
    const narrowed = query !== undefined && filterable(query);
    const rows = await this.reader.rows(
      "bn_string_list",
      {
        previewBytes: STRING_PREVIEW_BYTES,
        ...(address === undefined ? {} : { address }),
        ...(narrowed ? { query: query.pattern } : {}),
      },
      binjaStringRowSchema,
      front,
    );
    // Reading whole objects is affordable for one address or preselected hits.
    const complete = address !== undefined || narrowed;
    const matches = query === undefined ? () => true : matcher(query);
    const items: JsonValue[] = [];
    let cut = 0;
    for (const row of rows) {
      const value = await this.#stringValue(row, complete);
      if (!matches(value.item.value)) continue;
      if (value.cut) cut += 1;
      items.push(value.item);
    }
    if (cut > 0)
      this.reader.limit(
        `${String(cut)} returned string value(s) are cut at the first ${String(STRING_PREVIEW_BYTES)} bytes of a longer object; read_bytes returns the rest.`,
      );
    if (query !== undefined && !complete)
      this.reader.limit(
        `Objects longer than ${String(STRING_PREVIEW_BYTES)} bytes were matched on their first ${String(STRING_PREVIEW_BYTES)} bytes only.`,
      );
    if (narrowed)
      this.reader.limit(
        "Candidates were preselected by Binary Ninja's case-insensitive substring filter over string contents, then rechecked here.",
      );
    return items;
  }

  async names(address?: string): Promise<JsonValue> {
    const rows =
      address === undefined
        ? await this.reader.rows(
            "bn_symbol_list",
            {},
            binjaSymbolRowSchema,
            front,
          )
        : await this.#symbolsAt(address);
    return rows.map((row) => ({ address: row.symbol, value: row.fullName }));
  }

  async #symbolsAt(address: string) {
    const reply = await this.reader.text("bn_symbol_list_at", { address });
    return (reply.tables[0]?.rows ?? []).map((row) =>
      binjaSymbolRowSchema.parse(row),
    );
  }

  async addressName(address: string): Promise<JsonValue> {
    const symbols = await this.#symbolsAt(address);
    if (symbols.length > 1)
      this.reader.limit(
        `Binary Ninja lists ${String(symbols.length)} symbols at this address; the first is reported. list_names with this address returns all of them.`,
      );
    return symbols[0]?.fullName ?? null;
  }

  async comment(address: string): Promise<JsonValue> {
    const reply = await this.reader.structured(
      "bn_comment_get",
      { comment: address },
      binjaCommentSchema,
    );
    return reply.text === "" ? null : reply.text;
  }

  #segmentRows(): Promise<BinjaSegmentRow[]> {
    return this.reader.rows("bn_segment_list", {}, binjaSegmentRowSchema);
  }

  async segments(): Promise<JsonValue> {
    const segments = await this.#segmentRows();
    const sections = await this.reader.rows(
      "bn_section_list",
      {},
      binjaSectionRowSchema,
    );
    return segments.map((segment) => ({
      name: segment.start,
      start: segment.start,
      end: segment.end,
      readable: segment.readable,
      writable: segment.writable,
      executable: segment.executable,
      permissions: { available: true, source: SEGMENT_SOURCE },
      provenance: SEGMENT_SOURCE,
      sections: sections
        .filter(
          ({ start }) =>
            BigInt(start) >= BigInt(segment.start) &&
            BigInt(start) < BigInt(segment.end),
        )
        .map((section) => ({
          name: section.section,
          start: section.start,
          end: section.end,
          readable: null,
          writable: null,
          executable: null,
          permissions: {
            available: false,
            reason: `Binary Ninja reports section semantics (${section.semantics}), not permissions.`,
          },
          provenance: "binary-ninja-section",
        })),
    }));
  }

  async readBytes(address: string, length: number): Promise<JsonValue> {
    let hex = "";
    let complete = true;
    while (hex.length / 2 < length && complete) {
      const done = hex.length / 2;
      const wanted = Math.min(MEMORY_READ_BYTES, length - done);
      const read = await this.reader.structured(
        "bn_memory_read",
        { address: binjaHex(BigInt(address) + BigInt(done)), length: wanted },
        binjaMemoryReadSchema,
      );
      if (read.bytesRead * 2 !== read.hex.length || read.bytesRead > wanted)
        throw new AnalysisProtocolError(
          "Binary Ninja memory read disagrees with its own byte count.",
        );
      hex += read.hex.toLowerCase();
      complete = read.bytesRead === wanted;
    }
    return {
      address,
      requested_bytes: length,
      returned_bytes: hex.length / 2,
      bytes_hex: hex,
      complete,
    };
  }

  async fileOffset(address: string): Promise<JsonValue> {
    const at = BigInt(address);
    const segment = (await this.#segmentRows()).find(
      ({ start, end }) => at >= BigInt(start) && at < BigInt(end),
    );
    const delta = segment === undefined ? null : at - BigInt(segment.start);
    if (
      segment === undefined ||
      delta === null ||
      delta >= BigInt(segment.dataLength)
    )
      throw new AnalysisInputError("address_to_file_offset", undefined, [
        {
          path: ["address"],
          reason: "invalid_value",
          message:
            segment === undefined
              ? "The address lies outside every Binary Ninja segment."
              : "The address has no file-backed bytes in its Binary Ninja segment.",
        },
      ]);
    return { address, file_offset: segment.dataOffset + Number(delta) };
  }

  async containing(address: string): Promise<JsonValue> {
    const at = await this.reader.structured(
      "bn_data_at",
      { address },
      binjaDataAtSchema,
    );
    const [first] = at.functions;
    if (first === undefined) {
      const mapped = (await this.#segmentRows()).some(
        ({ start, end }) =>
          BigInt(address) >= BigInt(start) && BigInt(address) < BigInt(end),
      );
      return {
        query_address: address,
        found: false,
        procedure: null,
        reason: mapped ? "not_in_procedure" : "outside_segments",
      };
    }
    if (at.functions.length > 1)
      this.reader.limit(
        `Binary Ninja lists ${String(at.functions.length)} functions containing this address; the first is reported.`,
      );
    const fn = await this.functions.at(first.start);
    if (fn === null)
      throw new AnalysisProtocolError(
        "Binary Ninja named a containing function it could not then describe.",
      );
    return {
      query_address: address,
      found: true,
      procedure: binjaProcedureIdentity(fn),
    };
  }

  async xrefs(address: string): Promise<JsonValue> {
    const sources = new Set<string>();
    const fn = await this.functions.at(address);
    if (fn === null)
      this.reader.limit(
        "This address is not a function entry, so only data references are reported; code references to it are unknown.",
      );
    else {
      for (const { site } of await this.functions.callerSites(fn))
        sources.add(site);
      this.reader.limit(
        "Call sites and data references are reported. Jumps and other non-call code references to this entry cannot be told apart from references into the function body and are omitted.",
      );
    }
    for (const row of await this.reader.rows(
      "bn_data_xrefs_to",
      { address },
      binjaDataReferenceRowSchema,
    ))
      sources.add(row.Source);
    return [...sources];
  }
}

export { searchSchema as binjaSearchSchema };
