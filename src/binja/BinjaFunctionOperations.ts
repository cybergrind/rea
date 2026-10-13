import type { z } from "zod";
import {
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import {
  functionDossierSchema,
  functionInstructionWindowSchema,
  type functionBodySchema,
} from "../domain/hopperValues.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { BinjaToolError } from "./BinjaMcpConnection.js";
import {
  binjaAddressSchema,
  binjaBasicBlockRowSchema,
  binjaCalleeRowSchema,
  binjaCallerRowSchema,
  binjaCommentSchema,
  binjaFunctionMetaSchema,
  binjaFunctionRowSchema,
  binjaHex,
  binjaIncomingReferenceRowSchema,
  binjaOutgoingReferenceRowSchema,
  binjaStackRowSchema,
  parseBinjaFunctionReferences,
  parseBinjaRange,
  splitBinjaCell,
  type BinjaRange,
} from "./BinjaProtocolValues.js";
import { binjaLimitationsFor } from "./BinjaProviderCapabilities.js";
import type { BinjaToolReader } from "./BinjaToolReader.js";

type FunctionBody = z.infer<typeof functionBodySchema>;

/** One analyzed function with the complete body ranges Binary Ninja reports. */
export interface BinjaFunction {
  readonly address: string;
  readonly name: string;
  readonly definition: string | null;
  readonly basicBlockCount: number;
  readonly body: FunctionBody;
}

interface NamedFunction {
  readonly address: string;
  readonly name: string;
}
interface CallerSite {
  readonly site: string;
  readonly functions: NamedFunction[];
}
interface CalleeSite extends CallerSite {
  readonly target: string | null;
}

const otherBody = {
  available: false,
  reason: "Body ranges are reported only for the inspected procedure.",
} as const;
const kindUnavailable = {
  available: false,
  reason:
    "The Binary Ninja MCP lists reference endpoints without reference type flags.",
} as const;

const identity = (fn: BinjaFunction) => ({
  address: fn.address,
  name: fn.name,
  classification: null,
  body: fn.body,
});
const named = (ref: NamedFunction) => ({
  address: ref.address,
  name: ref.name,
  classification: null,
  body: otherBody,
});

const notFound = (query: string, message: string): AnalysisInputError =>
  new AnalysisInputError("procedure", undefined, [
    { path: ["procedure"], reason: "invalid_value", expected: query, message },
  ]);

/** Merge half-open ranges into ordered, disjoint, maximal inclusive ranges. */
const bodyOf = (
  entry: string,
  printed: readonly BinjaRange[],
): FunctionBody => {
  const merged: { start: bigint; end: bigint }[] = [];
  for (const range of [...printed].sort((a, b) =>
    a.start < b.start ? -1 : a.start > b.start ? 1 : 0,
  )) {
    const last = merged.at(-1);
    if (last !== undefined && range.start <= last.end)
      last.end = range.end > last.end ? range.end : last.end;
    else merged.push({ start: range.start, end: range.end });
  }
  const first = merged[0];
  const last = merged.at(-1);
  if (first === undefined || last === undefined)
    return {
      available: false,
      reason: "Binary Ninja reported no address range for this function.",
    };
  const total = merged.reduce((sum, r) => sum + (r.end - r.start), 0n);
  const span = last.end - first.start;
  if (span > BigInt(Number.MAX_SAFE_INTEGER))
    throw new AnalysisProtocolError(
      "Binary Ninja reported a function span beyond the safe integer range.",
    );
  const at = BigInt(entry);
  return {
    available: true,
    provenance: "binary-ninja-function-ranges",
    ranges: merged.map((r) => ({
      start: binjaHex(r.start),
      end: binjaHex(r.end - 1n),
    })),
    total_bytes: Number(total),
    span_bytes: Number(span),
    non_contiguous: merged.length > 1,
    contains_entry: merged.some((r) => at >= r.start && at < r.end),
  };
};

/** Drop the trailing parameter list of a rendered C++ name, template-aware. */
export const bareBinjaName = (full: string): string => {
  let name = full.trim();
  if (name.endsWith(" const")) name = name.slice(0, -" const".length);
  if (!name.endsWith(")")) return name;
  let depth = 0;
  for (let index = name.length - 1; index >= 0; index -= 1) {
    const char = name[index];
    if (char === ")") depth += 1;
    else if (char === "(") {
      depth -= 1;
      if (depth === 0) return name.slice(0, index);
    }
  }
  return name;
};

/** Function-scoped questions answered from an attached Binary Ninja. */
export class BinjaFunctionOperations {
  // One operation asks for the same call-site listing several times.
  readonly #callerSites = new Map<string, Promise<CallerSite[]>>();
  readonly #calleeSites = new Map<string, Promise<CalleeSite[]>>();

  constructor(private readonly reader: BinjaToolReader) {}

  /** Read one function by its exact entry; null when no function starts there. */
  async at(address: string): Promise<BinjaFunction | null> {
    let reply;
    try {
      reply = await this.reader.text("bn_function_info", { function: address });
    } catch (cause: unknown) {
      if (
        cause instanceof BinjaToolError &&
        cause.code === "function_not_found"
      )
        return null;
      throw cause;
    }
    const described = binjaFunctionMetaSchema.parse(reply.meta);
    if (described.function !== address)
      throw new AnalysisProtocolError(
        "Binary Ninja described a different function than the requested entry.",
      );
    const fields = new Map(
      (
        reply.tables.find(({ heading }) => heading === "Function")?.rows ?? []
      ).map((row) => [row.Field ?? "", row.Value ?? ""]),
    );
    const ranges = fields.get("Ranges");
    const blocks = fields.get("Basic Blocks");
    if (ranges === undefined || blocks === undefined || !/^\d+$/u.test(blocks))
      throw new AnalysisProtocolError(
        "Binary Ninja function summary omitted its ranges or basic block count.",
      );
    const definition = fields.get("Definition") ?? "";
    return {
      address,
      name: described.name,
      definition: definition === "" ? null : definition,
      basicBlockCount: Number(blocks),
      body: bodyOf(address, splitBinjaCell(ranges).map(parseBinjaRange)),
    };
  }

  /** Resolve an entry address or an unambiguous rendered or bare name. */
  async resolve(query: string): Promise<BinjaFunction> {
    if (/^0x[0-9a-f]+$/iu.test(query)) {
      const address = binjaAddressSchema.parse(query);
      const found = await this.at(address);
      if (found === null)
        throw notFound(
          query,
          `No analyzed function starts at ${address}. Use resolve_containing_procedure for an interior address.`,
        );
      return found;
    }
    // Names are matched against the listing rather than passed as a Binary
    // Ninja expression, which would also evaluate arithmetic and data symbols.
    const rows = await this.reader.rows(
      "bn_function_list",
      { query },
      binjaFunctionRowSchema,
      { retain: "front-matter" },
    );
    let matches = rows.filter(({ name }) => name === query);
    if (matches.length === 0)
      matches = rows.filter(({ name }) => {
        const bare = bareBinjaName(name);
        return bare === query || bare.endsWith(`::${query}`);
      });
    const [match] = matches;
    if (match === undefined)
      throw notFound(query, `No analyzed function is named ${query}.`);
    if (matches.length > 1)
      throw notFound(
        query,
        `${String(matches.length)} analyzed functions match ${query}; use an entry address instead.`,
      );
    const found = await this.at(match.function);
    if (found === null)
      throw new AnalysisProtocolError(
        "Binary Ninja listed a function it could not then describe.",
      );
    return found;
  }

  async #table<Schema extends z.ZodType>(
    tool: string,
    fn: BinjaFunction,
    schema: Schema,
  ): Promise<z.infer<Schema>[]> {
    return this.reader.rows(tool, { function: fn.address }, schema);
  }

  pseudocode(fn: BinjaFunction): Promise<string | null> {
    return this.reader.block("bn_function_decompile", fn.address);
  }

  /** Instruction lines as `address: text`; headers and block gaps are dropped. */
  async assembly(fn: BinjaFunction): Promise<string[]> {
    const text = await this.reader.block("bn_function_disassembly", fn.address);
    return (text ?? "").split("\n").flatMap((line) => {
      const match = /^\s*(0x[0-9a-f]+)\s+(.*\S)\s*$/iu.exec(line);
      return match === null
        ? []
        : [`${binjaAddressSchema.parse(match[1])}: ${match[2] ?? ""}`];
    });
  }

  /** Call sites that reach this function, each with its containing functions. */
  callerSites(fn: BinjaFunction): Promise<CallerSite[]> {
    const known = this.#callerSites.get(fn.address);
    if (known !== undefined) return known;
    const read = this.#readCallerSites(fn);
    this.#callerSites.set(fn.address, read);
    return read;
  }

  async #readCallerSites(fn: BinjaFunction): Promise<CallerSite[]> {
    const rows = await this.#table(
      "bn_function_callers",
      fn,
      binjaCallerRowSchema,
    );
    return rows.map((row) => ({
      site: row.Callsite,
      functions: parseBinjaFunctionReferences(row["Caller Function"]),
    }));
  }

  /** Call sites of this function with resolved functions or a bare target. */
  calleeSites(fn: BinjaFunction): Promise<CalleeSite[]> {
    const known = this.#calleeSites.get(fn.address);
    if (known !== undefined) return known;
    const read = this.#readCalleeSites(fn);
    this.#calleeSites.set(fn.address, read);
    return read;
  }

  async #readCalleeSites(fn: BinjaFunction): Promise<CalleeSite[]> {
    const rows = await this.#table(
      "bn_function_callees",
      fn,
      binjaCalleeRowSchema,
    );
    return rows.map((row) => {
      const target = binjaAddressSchema.safeParse(row["Callee Address"]);
      return {
        site: row.Callsite,
        target: target.success ? target.data : null,
        functions: parseBinjaFunctionReferences(row["Callee Functions"]),
      };
    });
  }

  async callers(fn: BinjaFunction) {
    const result = new Map<string, ReturnType<typeof named>>();
    for (const { functions } of await this.callerSites(fn))
      for (const ref of functions) result.set(ref.address, named(ref));
    return [...result.values()];
  }

  /** Resolved callees, plus call sites whose target is not an analyzed function. */
  async callees(fn: BinjaFunction) {
    const resolved = new Map<string, ReturnType<typeof named>>();
    const unresolved: { address: string; reason: string }[] = [];
    for (const { site, target, functions } of await this.calleeSites(fn)) {
      for (const ref of functions) resolved.set(ref.address, named(ref));
      if (functions.length === 0)
        unresolved.push({
          address: site,
          reason:
            target === null
              ? "Binary Ninja reported no target address for this call site."
              : `The target ${target} is not an analyzed function.`,
        });
    }
    if (unresolved.length > 0)
      this.reader.limit(
        "Some call sites have no analyzed callee function; they are reported as unresolved calls, not as callees.",
      );
    return { resolved: [...resolved.values()], unresolved };
  }

  async references(fn: BinjaFunction, direction: "incoming" | "outgoing") {
    const procedure = identity(fn);
    const edges = new Map<string, JsonValue>();
    if (direction === "incoming") {
      for (const { site, functions } of await this.callerSites(fn)) {
        const [source] = functions;
        edges.set(site, {
          source_address: site,
          target_address: fn.address,
          source_procedure: source === undefined ? null : named(source),
          target_procedure: procedure,
          kind: kindUnavailable,
        });
      }
      for (const row of await this.#table(
        "bn_function_xrefs_to",
        fn,
        binjaIncomingReferenceRowSchema,
      )) {
        const [source] = parseBinjaFunctionReferences(row["Source Function"]);
        // A reference from inside the function is its own control flow.
        if (source?.address === fn.address || edges.has(row.Source)) continue;
        edges.set(row.Source, {
          source_address: row.Source,
          target_address: fn.address,
          source_procedure: source === undefined ? null : named(source),
          target_procedure: procedure,
          kind: kindUnavailable,
        });
      }
      this.reader.limit(
        "Incoming non-call references name the function they enter, not the exact target; the entry address stands in for it. References from inside the function are omitted as its own control flow.",
      );
      return { edges: [...edges.values()], unresolved: [] };
    }
    const { unresolved } = await this.callees(fn);
    const called = new Set<string>();
    for (const { site, target, functions } of await this.calleeSites(fn)) {
      const address = functions[0]?.address ?? target;
      if (address === null) continue;
      called.add(address);
      edges.set(`${site}>${address}`, {
        source_address: site,
        target_address: address,
        source_procedure: procedure,
        target_procedure:
          functions[0] === undefined ? null : named(functions[0]),
        kind: kindUnavailable,
      });
    }
    for (const row of await this.#table(
      "bn_function_xrefs_from",
      fn,
      binjaOutgoingReferenceRowSchema,
    )) {
      // A called target already has an edge with its exact call site.
      if (called.has(row.Target)) continue;
      const source = binjaHex(parseBinjaRange(row["Source Range"]).start);
      const [target] = parseBinjaFunctionReferences(row["Target Functions"]);
      edges.set(`${source}>${row.Target}`, {
        source_address: source,
        target_address: row.Target,
        source_procedure: procedure,
        target_procedure: target === undefined ? null : named(target),
        kind: kindUnavailable,
      });
    }
    return { edges: [...edges.values()], unresolved };
  }

  async #locals(fn: BinjaFunction) {
    const rows = await this.#table(
      "bn_function_stack_layout",
      fn,
      binjaStackRowSchema,
    );
    return rows.map((row) => ({
      description: `${row.Definition} ${row.Variable}`.trim(),
      provenance: "binary-ninja-stack-layout",
      name: row.Variable === "" ? null : row.Variable,
      stack_displacement: row.Offset,
    }));
  }

  async #basicBlocks(fn: BinjaFunction) {
    const rows = await this.#table(
      "bn_function_basic_blocks",
      fn,
      binjaBasicBlockRowSchema,
    );
    return rows.map((row) => {
      const range = parseBinjaRange(row.Range);
      const successors = splitBinjaCell(row["Outgoing Edges"]).map((edge) => {
        const match = /#\d+\s+(0x[0-9a-f]+)-/iu.exec(edge);
        if (match === null)
          throw new AnalysisProtocolError(
            "Binary Ninja reported a basic block edge without a target range.",
          );
        return binjaAddressSchema.parse(match[1]);
      });
      return {
        start: binjaHex(range.start),
        end: binjaHex(range.end),
        successors: [...new Set(successors)].sort(),
      };
    });
  }

  async info(fn: BinjaFunction): Promise<JsonValue> {
    return {
      name: fn.name,
      entrypoint: fn.address,
      basicblock_count: fn.basicBlockCount,
      length: fn.body.available ? fn.body.total_bytes : 0,
      signature: fn.definition,
      locals: await this.#locals(fn),
      classification: null,
      body: fn.body,
    };
  }

  async instructions(fn: BinjaFunction): Promise<JsonValue> {
    return functionInstructionWindowSchema.parse({
      procedure: identity(fn),
      instructions: await this.assembly(fn),
      limitations: binjaLimitationsFor("read_function_instructions"),
    });
  }

  async dossier(fn: BinjaFunction): Promise<JsonValue> {
    const assembly = await this.assembly(fn);
    const pseudocode = await this.pseudocode(fn);
    const locals = await this.#locals(fn);
    const callers = await this.callers(fn);
    const incoming = await this.references(fn, "incoming");
    const outgoing = await this.references(fn, "outgoing");
    const callees = await this.callees(fn);
    const blocks = await this.#basicBlocks(fn);
    const comment = await this.reader.structured(
      "bn_comment_get",
      { comment: fn.address },
      binjaCommentSchema,
    );
    return functionDossierSchema.parse({
      procedure: { ...identity(fn), signature: fn.definition, locals },
      pseudocode: pseudocode ?? "",
      assembly,
      comments:
        comment.text === ""
          ? []
          : [{ address: fn.address, kind: "comment", text: comment.text }],
      callers,
      callees: callees.resolved,
      incoming_references: incoming.edges,
      outgoing_references: outgoing.edges,
      unresolved_calls: callees.unresolved,
      referenced_strings: [],
      referenced_names: [],
      basic_blocks: blocks,
      native_api: null,
      native_value_flow: null,
      limitations: [
        ...binjaLimitationsFor("analyze_function"),
        ...this.reader.limitations,
        "Only the comment at the function entry is read; comments at other addresses are unknown. Stack layout records are not evidence of source locals.",
        ...(pseudocode === null ? ["Pseudocode is unavailable."] : []),
      ],
    });
  }
}

export { identity as binjaProcedureIdentity };
