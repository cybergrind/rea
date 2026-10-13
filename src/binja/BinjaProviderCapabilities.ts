import type {
  AnalysisOperation,
  CapabilityDescriptor,
} from "../application/AnalysisProvider.js";

/** This version identifies REA's adapter, not Binary Ninja or its MCP plugin. */
export const BINJA_PROVIDER_IDENTITY = Object.freeze({
  id: "binja",
  name: "Binary Ninja MCP adapter",
  version: "1",
});

/** Read-only analyst outcomes served from an attached Binary Ninja. */
export const BINJA_OPERATIONS = Object.freeze([
  "list_documents",
  "list_procedures",
  "search_procedures",
  "list_strings",
  "search_strings",
  "list_names",
  "list_segments",
  "address_name",
  "comment",
  "read_bytes",
  "address_to_file_offset",
  "resolve_containing_procedure",
  "procedure_address",
  "procedure_info",
  "procedure_pseudo_code",
  "procedure_assembly",
  "procedure_callers",
  "procedure_callees",
  "procedure_references",
  "read_function_instructions",
  "xrefs",
  "analyze_function",
] as const satisfies readonly Exclude<AnalysisOperation, "health">[]);
export type BinjaOperation = (typeof BINJA_OPERATIONS)[number];

const READ_ONLY =
  "This adapter is read-only: it never edits, saves, closes, or opens an item in the attached Binary Ninja.";
const NO_CURSOR =
  "The Binary Ninja MCP exposes no GUI cursor or navigation state.";

/** Operations this adapter refuses, each with the reason it reports. */
export const BINJA_UNSUPPORTED_OPERATIONS = Object.freeze([
  ["annotate_native_function", READ_ONLY],
  ["set_address_name", READ_ONLY],
  ["set_addresses_names", READ_ONLY],
  ["set_comment", READ_ONLY],
  ["set_inline_comment", READ_ONLY],
  ["set_bookmark", READ_ONLY],
  ["unset_bookmark", READ_ONLY],
  ["current_address", NO_CURSOR],
  ["current_procedure", NO_CURSOR],
  ["current_document", NO_CURSOR],
  ["goto_address", `${NO_CURSOR} Moving it would also change GUI state.`],
  ["next_address", "The Binary Ninja MCP has no adjacent-object query."],
  ["prev_address", "The Binary Ninja MCP has no adjacent-object query."],
  ["list_bookmarks", "The Binary Ninja MCP has no bookmark or tag listing."],
  [
    "inline_comment",
    "Binary Ninja keeps one comment per address, served by the comment operation; it has no separate inline kind.",
  ],
  [
    "inspect_native_instruction",
    "The Binary Ninja MCP renders function text only; it reports no decoded bytes, operand tokens, or flow for one instruction.",
  ],
  [
    "inspect_native_load_image",
    "The Binary Ninja MCP reports no relocation or source-byte mapping digests to verify a loaded image.",
  ],
  [
    "resolve_native_call_targets",
    "Not mapped: bn_function_callees lists call sites and callee addresses, but this adapter does not yet translate them into the call-target contract.",
  ],
  [
    "inspect_native_data_type",
    "Not mapped: bn_type_info reports a type, but this adapter does not yet translate it into the data-type contract.",
  ],
] as const satisfies readonly (readonly [
  Exclude<AnalysisOperation, "health">,
  string,
])[]);

/** Tools the provider may call; every one only reads the attached database. */
export const BINJA_READ_ONLY_TOOLS: ReadonlySet<string> = new Set([
  "bn_binary_view_list",
  "bn_open_item_list",
  "bn_analysis_status",
  "bn_function_list",
  "bn_function_info",
  "bn_function_decompile",
  "bn_function_disassembly",
  "bn_function_callers",
  "bn_function_callees",
  "bn_function_xrefs_to",
  "bn_function_xrefs_from",
  "bn_function_basic_blocks",
  "bn_function_stack_layout",
  "bn_data_xrefs_to",
  "bn_data_at",
  "bn_string_list",
  "bn_symbol_list",
  "bn_symbol_list_at",
  "bn_segment_list",
  "bn_section_list",
  "bn_memory_read",
  "bn_comment_get",
]);

/** Shared limitations of observations from an externally mutable GUI database. */
export const BINJA_LIMITATIONS = Object.freeze([
  "Provider version identifies the REA Binary Ninja adapter. The Binary Ninja engine version is unknown; MCP serverInfo is reported independently.",
  "Results describe the current Binary Ninja analysis database, including analyst names and types. Input identity does not prove an unmodified database; patches, annotations, and database revision remain unknown.",
  "Binary Ninja reports no input hash. The target is bound by the active view's open item path, the raw view size, and the file bytes mapped at file offset zero; bytes beyond that header are not compared.",
  "Live results are never replayed from analysis snapshots. Target and active-view checks before and after a request do not provide an atomic lock against GUI changes.",
  "Binary Ninja answers one MCP caller at a time. This session serializes its own requests; other processes calling the same Binary Ninja are not coordinated.",
  "Caller cancellation drains the in-flight MCP request; it does not prove that Binary Ninja engine work was interrupted.",
]);

const OPERATION_LIMITATIONS: Partial<
  Record<BinjaOperation, readonly string[]>
> = {
  list_strings: [
    "Only Binary Ninja string objects are observed. Values are decoded from at most 256 preview bytes per object; a longer value is cut at that length and listed in the result limitations. Encoding termination is not reported.",
  ],
  search_strings: [
    "Only Binary Ninja string objects are observed. An ASCII literal pattern is filtered by Binary Ninja's case-insensitive substring match and rechecked here; other patterns walk every string object. A match beyond the first 256 preview bytes of an object is confirmed from its bytes, up to 65536 bytes per object.",
  ],
  search_procedures: [
    "An ASCII literal pattern is filtered by Binary Ninja's case-insensitive substring match and rechecked here; other patterns walk every function. Regex mode uses ECMAScript Unicode semantics.",
  ],
  list_names: [
    "The symbol inventory lists Binary Ninja symbols by full name; symbol binding and source facts are not reported.",
  ],
  list_segments: [
    "Segments are Binary Ninja memory segments named by their start address, with the sections each one fully contains. A section spanning several segments appears under none.",
  ],
  comment: [
    "The address comment of the active view is reported. A comment stored on a function at the same address is not distinguished.",
  ],
  read_bytes: [
    "Bytes reflect Binary Ninja's loaded view, including loader changes. A read stops at an unmapped byte and reports completeness explicitly.",
  ],
  address_to_file_offset: [
    "Offsets come from Binary Ninja segment file mappings. An address in a segment without file-backed bytes fails explicitly.",
  ],
  xrefs: [
    "A function entry reports its call sites and other code references. Any other address reports data references only: the Binary Ninja MCP has no query for code references to a data address, so those remain unknown.",
  ],
  procedure_references: [
    "Edges come from call-site and function reference listings; detailed reference flags are unavailable. Outgoing non-call references carry the source range start, not the exact instruction.",
  ],
  analyze_function: [
    "Referenced strings and names, comment inventories, and typed reference flags are unavailable; empty facets are unknown, not observed absence.",
  ],
};

const effects = Object.freeze({
  mutatesArtifact: false,
  launchesProcess: false,
  mayShowUi: false,
  mayAccessNetwork: true,
  mayWriteFilesystem: false,
  changesPermissions: false,
  requiresRoot: false,
});

/** Limitation text for one served operation, including the common base. */
export const binjaLimitationsFor = (
  operation: BinjaOperation,
): readonly string[] => [
  ...BINJA_LIMITATIONS,
  ...(OPERATION_LIMITATIONS[operation] ?? []),
];

/** Advertise served observations and name every refused operation's reason. */
export const BINJA_CAPABILITIES: readonly CapabilityDescriptor[] =
  Object.freeze([
    ...BINJA_OPERATIONS.map((operation) => ({
      provider: BINJA_PROVIDER_IDENTITY,
      operation,
      available: true as const,
      reason: null,
      cachePolicy: "live" as const,
      effects,
      limitations: binjaLimitationsFor(operation),
    })),
    ...BINJA_UNSUPPORTED_OPERATIONS.map(([operation, reason]) => ({
      provider: BINJA_PROVIDER_IDENTITY,
      operation,
      available: false as const,
      reason,
      cachePolicy: "live" as const,
      effects,
      limitations: BINJA_LIMITATIONS,
    })),
  ]);
