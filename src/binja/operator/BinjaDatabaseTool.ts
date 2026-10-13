import { existsSync, readdirSync, statSync } from "node:fs";
import { join, parse, resolve } from "node:path";
import { z } from "zod";
import type { JsonValue } from "../../domain/jsonValue.js";
import type { BinjaMcpConnection } from "../BinjaMcpConnection.js";
import {
  binjaAnalysisStatusSchema,
  parseBinjaText,
} from "../BinjaProtocolValues.js";
import { BINJA_READ_ONLY_TOOLS } from "../BinjaProviderCapabilities.js";
import { sameBinjaHostPath } from "../BinjaTargetBinding.js";

const DATABASE_SUFFIX = ".bndb";
const IDLE_STATE = "IdleState";
const LIST_LIMIT = 1000;
/** Opening a saved database of a large binary takes minutes. */
const OPEN_TIMEOUT_MS = 1_800_000;
/** Saving a large database blocks Binary Ninja for minutes. */
const SAVE_TIMEOUT_MS = 3_600_000;

/** The three state-changing tools this operator tool may call by itself. */
export const BINJA_DATABASE_MUTATING_TOOLS = Object.freeze([
  "bn_open_item_open",
  "bn_binary_view_set_active",
  "bn_open_item_save",
] as const);

/** Closing an item discards unsaved analysis; only a person does that. */
export const BINJA_NEVER_CALLED_TOOLS: ReadonlySet<string> = new Set([
  "bn_open_item_close",
]);

/** Everything the database tool's own subcommands are allowed to call. */
export const BINJA_DATABASE_TOOLS: ReadonlySet<string> = new Set([
  ...BINJA_READ_ONLY_TOOLS,
  ...BINJA_DATABASE_MUTATING_TOOLS,
]);

/** Process exit codes shared by every subcommand. */
export const BINJA_DATABASE_EXIT = Object.freeze({
  ok: 0,
  refused: 2,
  notIdle: 3,
});

const itemSchema = z.looseObject({
  openItem: z.string().min(1),
  path: z.string(),
  modified: z.enum(["true", "false"]).transform((v) => v === "true"),
});
type OpenItem = z.infer<typeof itemSchema>;
const viewSchema = z.looseObject({
  binaryView: z.string().min(1),
  openItem: z.string().min(1),
  recommended: z.enum(["true", "false"]).transform((v) => v === "true"),
});

/** What `open` will do, decided before anything is called. */
export interface BinjaOpenPlan {
  readonly action: "activate" | "open-database" | "open-binary" | "refuse";
  readonly reason: string;
  readonly path?: string;
  readonly item?: string;
}

/** The newest saved database beside a binary: `<name>.bndb` or `<stem>.bndb`. */
export const binjaDatabaseFor = (binary: string): string | undefined => {
  const { dir, name } = parse(binary);
  const found = [
    ...new Set([
      `${binary}${DATABASE_SUFFIX}`,
      join(dir, name + DATABASE_SUFFIX),
    ]),
  ].filter((path) => existsSync(path) && statSync(path).isFile());
  return found.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
};

/**
 * Prefer what avoids a new analysis: an item already open, then the saved
 * database, and only then the binary. A second item is refused unless asked
 * for, because two large analyses rarely fit in memory together.
 */
export const planBinjaOpen = (
  binary: string,
  items: readonly Pick<OpenItem, "openItem" | "path">[],
  allowSecond = false,
): BinjaOpenPlan => {
  if (!existsSync(binary) || !statSync(binary).isFile())
    return { action: "refuse", reason: `${binary} is not a file` };
  const database = binjaDatabaseFor(binary);
  const wanted = [binary, ...(database === undefined ? [] : [database])];
  const open = items.find((item) =>
    wanted.some((path) => sameBinjaHostPath(resolve(item.path), resolve(path))),
  );
  if (open !== undefined)
    return {
      action: "activate",
      reason: `already open as ${open.openItem}`,
      path: open.path,
      item: open.openItem,
    };
  if (items.length > 0 && !allowSecond)
    return {
      action: "refuse",
      reason: `other items are open: ${items.map((item) => `${item.openItem} (${parse(item.path).base})`).join(", ")}; open a second one only with --allow-second`,
    };
  return database === undefined
    ? {
        action: "open-binary",
        reason: "no saved database: a full analysis starts",
        path: binary,
      }
    : {
        action: "open-database",
        reason: "saved database found, no new analysis needed",
        path: database,
      };
};

/** List saved databases under a directory tree, oldest path order. */
export const findBinjaDatabases = (root: string): string[] =>
  existsSync(root)
    ? readdirSync(root, { recursive: true, encoding: "utf8" })
        .filter((name) => name.endsWith(DATABASE_SUFFIX))
        .map((name) => join(root, name))
        .filter((path) => statSync(path).isFile())
        .sort()
    : [];

const rows = (reply: JsonValue): Readonly<Record<string, string>>[] => {
  if (typeof reply !== "string")
    throw new TypeError("Binary Ninja returned a structured listing");
  return [...(parseBinjaText(reply).tables[0]?.rows ?? [])];
};

/** Output and timing seams of one database command. */
export interface BinjaDatabaseHost {
  readonly print: (line: string) => void;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
}

/**
 * Operator commands over an attached Binary Ninja. Unlike the analysis
 * provider, `open` and `save` change GUI state; each does so only when its
 * subcommand is invoked, and nothing here closes an item or retries a save.
 */
export class BinjaDatabaseTool {
  constructor(
    private readonly connection: BinjaMcpConnection,
    private readonly host: BinjaDatabaseHost,
  ) {}

  async #items(): Promise<OpenItem[]> {
    return rows(
      await this.connection.call("bn_open_item_list", { limit: LIST_LIMIT }),
    ).map((row) => itemSchema.parse(row));
  }

  async #state(): Promise<{ state: string; progress: string }> {
    const { analysis } = binjaAnalysisStatusSchema.parse(
      await this.connection.call("bn_analysis_status", {}),
    );
    return {
      state: analysis.state,
      progress: `${String(analysis.progress?.count ?? 0)}/${String(analysis.progress?.total ?? 0)}`,
    };
  }

  /** Saved databases on disk and the items open now. */
  async list(root: string): Promise<number> {
    for (const path of findBinjaDatabases(root)) {
      const { mtime, size } = statSync(path);
      this.host.print(
        `saved  ${mtime.toISOString()}  ${(size / 2 ** 30).toFixed(1)} GiB  ${path}`,
      );
    }
    for (const item of await this.#items())
      this.host.print(
        `open   ${item.openItem}  unsaved-changes=${String(item.modified)}  ${item.path}`,
      );
    return BINJA_DATABASE_EXIT.ok;
  }

  /** Open the saved database when one exists, else the binary; then activate its view. */
  async open(binary: string, allowSecond: boolean): Promise<number> {
    const plan = planBinjaOpen(binary, await this.#items(), allowSecond);
    this.host.print(`${plan.action}: ${plan.reason}`);
    if (plan.action === "refuse" || plan.path === undefined)
      return BINJA_DATABASE_EXIT.refused;
    const path = resolve(plan.path);
    let item = plan.item;
    if (item === undefined) {
      await this.connection.call(
        "bn_open_item_open",
        { path },
        { timeoutMs: OPEN_TIMEOUT_MS },
      );
      item = (await this.#items()).find((entry) =>
        sameBinjaHostPath(resolve(entry.path), path),
      )?.openItem;
    }
    // The server does not follow the GUI's focused tab: activate explicitly.
    const view = rows(
      await this.connection.call("bn_binary_view_list", { limit: LIST_LIMIT }),
    )
      .map((row) => viewSchema.parse(row))
      .find((row) => row.openItem === item && row.recommended);
    if (view !== undefined)
      await this.connection.call("bn_binary_view_set_active", {
        binaryView: view.binaryView,
      });
    const { state, progress } = await this.#state();
    this.host.print(
      `item=${item ?? "unknown"} view=${view?.binaryView ?? "none"} state=${state} progress=${progress}`,
    );
    return view === undefined
      ? BINJA_DATABASE_EXIT.refused
      : BINJA_DATABASE_EXIT.ok;
  }

  /** Report the analysis state of the active view. */
  async status(): Promise<number> {
    const { state, progress } = await this.#state();
    this.host.print(`state=${state} progress=${progress}`);
    return state === IDLE_STATE
      ? BINJA_DATABASE_EXIT.ok
      : BINJA_DATABASE_EXIT.notIdle;
  }

  /** Poll until idle; give up once another poll would pass the limit. */
  async wait(limitMs: number, intervalMs: number): Promise<number> {
    const now = this.host.now ?? Date.now;
    const sleep =
      this.host.sleep ??
      ((ms: number) => new Promise<void>((done) => setTimeout(done, ms)));
    const deadline = now() + limitMs;
    for (;;) {
      const { state, progress } = await this.#state();
      this.host.print(
        `${new Date(now()).toISOString()} state=${state} progress=${progress}`,
      );
      if (state === IDLE_STATE) return BINJA_DATABASE_EXIT.ok;
      if (now() + intervalMs > deadline) return BINJA_DATABASE_EXIT.notIdle;
      await sleep(intervalMs);
    }
  }

  /** Save one open item of an idle view; a save is never retried. */
  async save(item: string): Promise<number> {
    const { state } = await this.#state();
    if (state !== IDLE_STATE) {
      this.host.print(`analysis is ${state}; save only an idle view`);
      return BINJA_DATABASE_EXIT.notIdle;
    }
    if (!(await this.#items()).some(({ openItem }) => openItem === item)) {
      this.host.print(`${item} is not an open item`);
      return BINJA_DATABASE_EXIT.refused;
    }
    const reply = await this.connection.call(
      "bn_open_item_save",
      { openItem: item },
      { timeoutMs: SAVE_TIMEOUT_MS },
    );
    this.host.print(typeof reply === "string" ? reply : JSON.stringify(reply));
    return BINJA_DATABASE_EXIT.ok;
  }

  /** Forward one raw tool call; the connection's authority still applies. */
  async call(
    tool: string,
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<number> {
    const reply = await this.connection.call(tool, args);
    this.host.print(typeof reply === "string" ? reply : JSON.stringify(reply));
    return BINJA_DATABASE_EXIT.ok;
  }
}
