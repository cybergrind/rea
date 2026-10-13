import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, realpath, stat } from "node:fs/promises";
import { normalize, parse, join } from "node:path";
import {
  AnalysisArtifactChangedError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { BinjaMcpConnection } from "./BinjaMcpConnection.js";
import {
  binjaAddressSchema,
  binjaAnalysisStatusSchema,
  binjaMemoryReadSchema,
  binjaOpenItemRowSchema,
  binjaSegmentRowSchema,
  binjaViewRowSchema,
  parseBinjaText,
  type BinjaViewRow,
} from "./BinjaProtocolValues.js";

const LIST_LIMIT = 1000;
const HEADER_BYTES = 256;
const IDLE_STATE = "IdleState";
const DATABASE_SUFFIX = ".bndb";

/** Compare host-local paths without confusing Windows paths with POSIX coordinates. */
export const sameBinjaHostPath = (left: string, right: string): boolean =>
  process.platform === "win32"
    ? normalize(left).toLowerCase() === normalize(right).toLowerCase()
    : normalize(left) === normalize(right);

const canonical = async (path: string): Promise<string> => {
  try {
    return await realpath(path);
  } catch {
    return normalize(path);
  }
};

const digest = async (path: string): Promise<string> => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
};

const rowsOf = (reply: JsonValue, tool: string) => {
  if (typeof reply !== "string")
    throw new AnalysisProtocolError(
      `Binary Ninja MCP tool ${tool} returned a structured result where text was expected.`,
    );
  return parseBinjaText(reply).tables[0]?.rows ?? [];
};

type PathRelation = "target" | "sibling-database" | "unrelated";

/**
 * The attached GUI is not in a state this session can analyze. The reason
 * and recovery reach the caller: only an operator can restore the view.
 */
const bindingFailure = (reason: string, recovery: string) =>
  new ProviderAdapterError("binja", "target_binding", {
    userMessage: `${reason} ${recovery}`,
    diagnostics: { reason, recovery },
  });

/**
 * Binds one REA target to the active view of an attached Binary Ninja.
 *
 * Binary Ninja reports no input hash, so the binding rests on facts it does
 * report: the open item's path, the raw view's size, and the bytes it maps at
 * file offset zero. Every later request re-reads the active view and fails
 * when it is no longer the bound one.
 */
export class BinjaTargetBinding {
  #identity: string | undefined;
  #file: { size: number; mtimeMs: number } | undefined;
  #facts: Record<string, JsonValue> = {};
  readonly limitations: string[] = [];

  constructor(
    private readonly connection: BinjaMcpConnection,
    private readonly target: BinaryTarget,
  ) {}

  async #views(): Promise<BinjaViewRow[]> {
    const tool = "bn_binary_view_list";
    return rowsOf(
      await this.connection.call(tool, { limit: LIST_LIMIT }),
      tool,
    ).map((row) => binjaViewRowSchema.parse(row));
  }

  async #pathRelation(itemPath: string): Promise<PathRelation> {
    const item = await canonical(itemPath);
    const target = await canonical(this.target.path);
    if (sameBinjaHostPath(item, target)) return "target";
    const { dir, name } = parse(target);
    return [
      `${target}${DATABASE_SUFFIX}`,
      join(dir, `${name}${DATABASE_SUFFIX}`),
    ].some((database) => sameBinjaHostPath(item, database))
      ? "sibling-database"
      : "unrelated";
  }

  /** Compare the bytes Binary Ninja maps at file offset zero with the file. */
  async #headerMatches(): Promise<boolean | null> {
    const tool = "bn_segment_list";
    const segment = rowsOf(
      await this.connection.call(tool, { limit: LIST_LIMIT }),
      tool,
    )
      .map((row) => binjaSegmentRowSchema.parse(row))
      .find(({ dataOffset, dataLength }) => dataOffset === 0 && dataLength > 0);
    const length = Math.min(
      segment?.dataLength ?? 0,
      this.#file?.size ?? 0,
      HEADER_BYTES,
    );
    if (segment === undefined || length === 0) return null;
    const read = binjaMemoryReadSchema.parse(
      await this.connection.call("bn_memory_read", {
        address: segment.start,
        length,
      }),
    );
    const handle = await open(this.target.path, "r");
    try {
      const bytes = Buffer.alloc(length);
      const { bytesRead } = await handle.read(bytes, 0, length, 0);
      return (
        bytesRead === length && bytes.toString("hex") === read.hex.toLowerCase()
      );
    } finally {
      await handle.close();
    }
  }

  async #bind(views: readonly BinjaViewRow[], active: BinjaViewRow) {
    const file = await stat(this.target.path);
    if ((await digest(this.target.path)) !== this.target.sha256.toLowerCase())
      throw new AnalysisArtifactChangedError(
        "target_binding",
        this.target.path,
        "its SHA-256 no longer matches the admitted target; reopen it",
      );
    this.#file = { size: file.size, mtimeMs: file.mtimeMs };
    const tool = "bn_open_item_list";
    const item = rowsOf(
      await this.connection.call(tool, { limit: LIST_LIMIT }),
      tool,
    )
      .map((row) => binjaOpenItemRowSchema.parse(row))
      .find(({ openItem }) => openItem === active.openItem);
    if (item === undefined)
      throw new AnalysisProtocolError(
        "Binary Ninja lists no open item for its active view.",
      );
    const relation = await this.#pathRelation(item.path);
    const raw = views.find(
      (view) =>
        view.openItem === active.openItem &&
        view.viewType === "Raw" &&
        binjaAddressSchema.safeParse(view.start).data === "0x0" &&
        binjaAddressSchema.safeParse(view.end).success,
    );
    const rawSize = raw === undefined ? null : Number(BigInt(raw.end));
    const header = await this.#headerMatches();
    const mismatch =
      (rawSize !== null && rawSize !== file.size) || header === false;
    if (mismatch || (relation === "unrelated" && rawSize === null && !header))
      throw bindingFailure(
        `The active Binary Ninja view (${active.binaryView}, ${item.path}) does not hold the selected target ${this.target.path}${mismatch ? ": its raw size or header bytes differ" : ""}.`,
        "Activate the view of that target, or of its saved database, in Binary Ninja and retry.",
      );
    if (relation === "unrelated")
      this.limitations.push(
        "The active Binary Ninja item is stored at a path unrelated to the target; it was accepted because its raw size and header bytes match.",
      );
    if (rawSize === null || header === null)
      this.limitations.push(
        "Binary Ninja exposed no raw view or no bytes mapped at file offset zero, so the target binding rests on fewer content checks.",
      );
    this.#facts = {
      open_item_path: item.path,
      open_item_kind: item.kind,
      path_relation: relation,
      raw_view_bytes: rawSize,
      header_bytes_match: header,
      target_sha256: this.target.sha256,
    };
  }

  /** Re-read the active view; fail when it is not the bound, idle target view. */
  async observe(): Promise<JsonValue> {
    const views = await this.#views();
    const active = views.filter((view) => view.active);
    const [view] = active;
    if (view === undefined || active.length !== 1)
      throw bindingFailure(
        `Binary Ninja reports ${String(active.length)} active views where exactly one is required.`,
        "Activate the target's view in Binary Ninja and retry.",
      );
    const identity = JSON.stringify([
      view.binaryView,
      view.openItem,
      view.viewType,
      binjaAddressSchema.parse(view.start),
      binjaAddressSchema.parse(view.end),
    ]);
    if (this.#identity === undefined) {
      await this.#bind(views, view);
      this.#identity = identity;
    } else if (identity !== this.#identity)
      throw bindingFailure(
        "The active Binary Ninja view or its image base changed during the REA session.",
        "Activate the bound view again, or reopen the target to bind the new one.",
      );
    const file = await stat(this.target.path);
    if (file.size !== this.#file?.size || file.mtimeMs !== this.#file.mtimeMs)
      throw new AnalysisArtifactChangedError(
        "target_binding",
        this.target.path,
        "its size or modification time changed during the REA session; reopen it",
      );
    const status = binjaAnalysisStatusSchema.parse(
      await this.connection.call("bn_analysis_status", {}),
    );
    if (status.analysis.state !== IDLE_STATE)
      throw bindingFailure(
        `Binary Ninja analysis is ${status.analysis.state}, not ${IDLE_STATE}; partial analysis is not served.`,
        "Retry after analysis completes.",
      );
    return {
      binary_view: view.binaryView,
      open_item: view.openItem,
      view_type: view.viewType,
      image_base: binjaAddressSchema.parse(view.start),
      end: binjaAddressSchema.parse(view.end),
      architecture: view.architecture,
      platform: view.platform,
      analysis_state: status.analysis.state,
      ...this.#facts,
    };
  }
}
