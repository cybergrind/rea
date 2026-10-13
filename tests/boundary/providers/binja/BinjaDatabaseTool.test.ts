import { utimes, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  BINJA_DATABASE_MUTATING_TOOLS,
  BINJA_DATABASE_TOOLS,
  BINJA_NEVER_CALLED_TOOLS,
  BinjaDatabaseTool,
  binjaDatabaseFor,
  findBinjaDatabases,
  planBinjaOpen,
} from "../../../../src/binja/operator/BinjaDatabaseTool.js";
import { BINJA_READ_ONLY_TOOLS } from "../../../../src/binja/BinjaProviderCapabilities.js";
import type { JsonValue } from "../../../../src/domain/jsonValue.js";
import {
  BINJA_LISTING_HEADERS,
  binjaPage,
  binjaRequest,
  scriptedBinjaConnection,
} from "../../../fixtures/binjaMcp.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

// Listings and the analysis status reproduce observed reply shapes. The replies
// of bn_open_item_open, bn_binary_view_set_active and bn_open_item_save are
// placeholders: those tools change GUI state and were never called against a
// real Binary Ninja. The tool under test does not interpret them.
const LIST = { limit: 1000 };
const itemRow = (handle: string, path: string, modified = false) => [
  handle,
  path.endsWith(".bndb") ? "database" : "file",
  path.split("/").at(-1) ?? "",
  path,
  "",
  "978945138564900512",
  String(modified),
  "false",
  "true",
  String(path.endsWith(".bndb")),
  "true",
];
const items = (...rows: string[][]) =>
  binjaPage("bn_open_item_list", LIST, {
    headers: BINJA_LISTING_HEADERS.items,
    rows,
  });
const viewRow = (
  view: string,
  item: string,
  type: string,
  recommended: boolean,
) => [
  view,
  item,
  type,
  type,
  "true",
  "false",
  "true",
  String(recommended),
  "x86_64",
  "windows-x86_64",
  "8",
  "0x180000000",
  "0x180001000",
  "0x180000400",
  "false",
  "false",
];
const views = (...rows: string[][]) =>
  binjaPage("bn_binary_view_list", LIST, {
    headers: BINJA_LISTING_HEADERS.views,
    rows,
  });
const status = (state: string, count = 0, total = 0) => ({
  analysis: {
    state,
    stateValue: 2,
    progress: { state, stateValue: 2, count, total },
    info: { state, stateValue: 2, analysisTime: 0, active: [] },
  },
  warnings: [],
});
const ITEMS = binjaRequest("bn_open_item_list", LIST);
const VIEWS = binjaRequest("bn_binary_view_list", LIST);
const STATUS = binjaRequest("bn_analysis_status", {});

const tool = (script: readonly (readonly [string, JsonValue | Error])[]) => {
  const connection = scriptedBinjaConnection(new Map(script));
  const lines: string[] = [];
  let time = 0;
  const sleeps: number[] = [];
  return {
    connection,
    lines,
    sleeps,
    database: new BinjaDatabaseTool(connection, {
      print: (line) => lines.push(line),
      now: () => time,
      sleep: async (ms) => {
        sleeps.push(ms);
        time += ms;
      },
    }),
  };
};
const binaries = async () => {
  const root = await createTestTempDirectory("rea-binja-db-");
  const binary = join(root, "core", "chrome.dll");
  await mkdir(join(root, "core"));
  await writeFile(binary, "binary");
  return { root, binary };
};

describe("choosing what to open", () => {
  it("finds the newest saved database under either naming scheme", async () => {
    const { root, binary } = await binaries();
    expect(binjaDatabaseFor(binary)).toBeUndefined();
    const stem = join(root, "core", "chrome.bndb");
    const named = `${binary}.bndb`;
    await writeFile(stem, "old");
    await writeFile(named, "new");
    await utimes(stem, new Date(1_000_000), new Date(1_000_000));
    expect(binjaDatabaseFor(binary)).toBe(named);
    await utimes(named, new Date(500_000), new Date(500_000));
    expect(binjaDatabaseFor(binary)).toBe(stem);
    expect(findBinjaDatabases(root)).toEqual([stem, named]);
    expect(findBinjaDatabases(join(root, "absent"))).toEqual([]);
  });

  it("prefers an open item, then the database, then the binary", async () => {
    const { root, binary } = await binaries();
    expect(planBinjaOpen(join(root, "missing.exe"), [])).toMatchObject({
      action: "refuse",
    });
    expect(planBinjaOpen(binary, [])).toEqual({
      action: "open-binary",
      reason: "no saved database: a full analysis starts",
      path: binary,
    });
    const database = `${binary}.bndb`;
    await writeFile(database, "db");
    expect(planBinjaOpen(binary, [])).toMatchObject({
      action: "open-database",
      path: database,
    });
    expect(
      planBinjaOpen(binary, [
        { openItem: "item_1", path: "/elsewhere/other.exe" },
        { openItem: "item_2", path: database },
      ]),
    ).toEqual({
      action: "activate",
      reason: "already open as item_2",
      path: database,
      item: "item_2",
    });
  });

  it("refuses a second item unless it was asked for", async () => {
    const { binary } = await binaries();
    const other = [{ openItem: "item_1", path: "/elsewhere/other.exe.bndb" }];
    expect(planBinjaOpen(binary, other)).toMatchObject({
      action: "refuse",
      reason: expect.stringContaining("item_1 (other.exe.bndb)"),
    });
    expect(planBinjaOpen(binary, other, true)).toMatchObject({
      action: "open-binary",
    });
  });
});

describe("database commands", () => {
  it("lists saved databases and open items with their unsaved state", async () => {
    const { root, binary } = await binaries();
    await writeFile(`${binary}.bndb`, "db");
    const { database, lines } = tool([
      [ITEMS, items(itemRow("item_2", `${binary}.bndb`, true))],
    ]);
    expect(await database.list(root)).toBe(0);
    expect(lines).toEqual([
      expect.stringMatching(
        new RegExp(`^saved  \\S+  0\\.0 GiB  ${binary}\\.bndb$`, "u"),
      ),
      `open   item_2  unsaved-changes=true  ${binary}.bndb`,
    ]);
  });

  it("opens the saved database, then activates its recommended view", async () => {
    const { binary } = await binaries();
    const path = `${binary}.bndb`;
    await writeFile(path, "db");
    const open = binjaRequest("bn_open_item_open", { path });
    const activate = binjaRequest("bn_binary_view_set_active", {
      binaryView: "view_3",
    });
    let opened = false;
    const connection = scriptedBinjaConnection(
      new Map<string, JsonValue>([
        [open, { openItem: "item_2" }],
        [
          VIEWS,
          views(
            viewRow("view_3", "item_2", "PE", true),
            viewRow("view_4", "item_2", "Raw", false),
          ),
        ],
        [activate, { binaryView: "view_3" }],
        [STATUS, status("AnalyzeState", 12, 90)],
      ]),
    );
    const lines: string[] = [];
    const database = new BinjaDatabaseTool(
      {
        ...connection,
        async call(name, args, options) {
          if (name === "bn_open_item_list") {
            connection.calls.push(binjaRequest(name, args));
            return opened ? items(itemRow("item_2", path)) : items();
          }
          if (name === "bn_open_item_open") {
            opened = true;
            // A saved database of a large binary takes minutes to open.
            expect(options?.timeoutMs).toBe(1_800_000);
          }
          return connection.call(name, args);
        },
      },
      { print: (line) => lines.push(line) },
    );
    expect(await database.open(binary, false)).toBe(0);
    expect(connection.calls).toEqual([
      ITEMS,
      open,
      ITEMS,
      VIEWS,
      activate,
      STATUS,
    ]);
    expect(lines).toEqual([
      "open-database: saved database found, no new analysis needed",
      "item=item_2 view=view_3 state=AnalyzeState progress=12/90",
    ]);
  });

  it("activates an already open item without opening it again", async () => {
    const { binary } = await binaries();
    const { database, connection, lines } = tool([
      [ITEMS, items(itemRow("item_2", binary))],
      [VIEWS, views(viewRow("view_3", "item_2", "PE", true))],
      [
        binjaRequest("bn_binary_view_set_active", { binaryView: "view_3" }),
        { binaryView: "view_3" },
      ],
      [STATUS, status("IdleState")],
    ]);
    expect(await database.open(binary, false)).toBe(0);
    expect(
      connection.calls.some((call) => call.startsWith("bn_open_item_open")),
    ).toBe(false);
    expect(lines[0]).toBe("activate: already open as item_2");
  });

  it("refuses to open beside another item and calls nothing that changes state", async () => {
    const { binary } = await binaries();
    const { database, connection, lines } = tool([
      [ITEMS, items(itemRow("item_1", "/elsewhere/other.exe.bndb"))],
    ]);
    expect(await database.open(binary, false)).toBe(2);
    expect(connection.calls).toEqual([ITEMS]);
    expect(lines).toEqual([
      expect.stringMatching(/^refuse: other items are open/u),
    ]);
  });
});

describe("database state commands", () => {
  it("reports the analysis state through its exit code", async () => {
    const idle = tool([[STATUS, status("IdleState")]]);
    expect(await idle.database.status()).toBe(0);
    expect(idle.lines).toEqual(["state=IdleState progress=0/0"]);
    const busy = tool([[STATUS, status("ExtendedAnalyzeState", 3, 9)]]);
    expect(await busy.database.status()).toBe(3);
    expect(busy.lines).toEqual(["state=ExtendedAnalyzeState progress=3/9"]);
  });

  it("waits a bounded time and never past its limit", async () => {
    const busy = tool([[STATUS, status("AnalyzeState", 1, 5)]]);
    expect(await busy.database.wait(150_000, 60_000)).toBe(3);
    // Polls at 0, 60 and 120 s; a fourth poll would pass the 150 s limit.
    expect(busy.sleeps).toEqual([60_000, 60_000]);
    expect(busy.lines).toHaveLength(3);
    const idle = tool([[STATUS, status("IdleState")]]);
    expect(await idle.database.wait(150_000, 60_000)).toBe(0);
    expect(idle.sleeps).toEqual([]);
  });

  it("saves one named item of an idle view exactly once", async () => {
    const save = binjaRequest("bn_open_item_save", { openItem: "item_2" });
    const saved = tool([
      [STATUS, status("IdleState")],
      [ITEMS, items(itemRow("item_2", "/core/chrome.dll.bndb", true))],
      [save, { openItem: "item_2", saved: true }],
    ]);
    expect(await saved.database.save("item_2")).toBe(0);
    expect(saved.connection.calls).toEqual([STATUS, ITEMS, save]);
    expect(saved.lines).toEqual(['{"openItem":"item_2","saved":true}']);
  });

  it("does not save while analysis runs, an unknown item, or again after a failure", async () => {
    const busy = tool([[STATUS, status("AnalyzeState")]]);
    expect(await busy.database.save("item_2")).toBe(3);
    expect(busy.connection.calls).toEqual([STATUS]);
    const unknown = tool([
      [STATUS, status("IdleState")],
      [ITEMS, items(itemRow("item_1", "/core/other.bndb"))],
    ]);
    expect(await unknown.database.save("item_2")).toBe(2);
    expect(unknown.connection.calls).toEqual([STATUS, ITEMS]);
    const save = binjaRequest("bn_open_item_save", { openItem: "item_2" });
    const failing = tool([
      [STATUS, status("IdleState")],
      [ITEMS, items(itemRow("item_2", "/core/chrome.dll.bndb"))],
      [save, new Error("Request timed out")],
    ]);
    await expect(failing.database.save("item_2")).rejects.toThrow(
      "Request timed out",
    );
    expect(
      failing.connection.calls.filter((call) => call === save),
    ).toHaveLength(1);
  });

  it("forwards a raw call and prints its reply", async () => {
    const request = binjaRequest("bn_comment_get", { comment: "0x1000" });
    const { database, lines } = tool([
      [request, { comment: "0x1000", text: "note", warnings: [] }],
    ]);
    expect(await database.call("bn_comment_get", { comment: "0x1000" })).toBe(
      0,
    );
    expect(lines).toEqual(['{"comment":"0x1000","text":"note","warnings":[]}']);
  });
});

it("keeps the provider's authority apart from the operator's", () => {
  expect(BINJA_DATABASE_MUTATING_TOOLS).toEqual([
    "bn_open_item_open",
    "bn_binary_view_set_active",
    "bn_open_item_save",
  ]);
  for (const name of BINJA_DATABASE_MUTATING_TOOLS) {
    expect(BINJA_READ_ONLY_TOOLS.has(name)).toBe(false);
    expect(BINJA_DATABASE_TOOLS.has(name)).toBe(true);
  }
  for (const name of BINJA_NEVER_CALLED_TOOLS) {
    expect(BINJA_DATABASE_TOOLS.has(name)).toBe(false);
    expect(BINJA_READ_ONLY_TOOLS.has(name)).toBe(false);
  }
});
