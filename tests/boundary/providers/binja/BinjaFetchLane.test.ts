import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  acquireBinjaLock,
  BinjaLockHeldError,
} from "../../../../src/binja/operator/BinjaExclusiveLock.js";
import {
  BinjaFetchError,
  BinjaFetchLane,
  readFetchQueue,
  runBinjaFetchLane,
  type BinjaFetchRequest,
} from "../../../../src/binja/operator/BinjaFetchLane.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const decompiled = (address: string) =>
  JSON.stringify({
    evidence_id: `ev_${address}`,
    provider: { id: "binja", name: "Binary Ninja MCP adapter", version: "1" },
    operation: "procedure_pseudo_code",
    normalized_result: `int64_t sub_${address.slice(2)}()\n{\n    return 0;\n}`,
  });
const dossier = (address: string) =>
  JSON.stringify({
    evidence_id: `ev_full_${address}`,
    provider: { id: "binja", name: "Binary Ninja MCP adapter", version: "1" },
    operation: "analyze_function",
    normalized_result: {
      pseudocode: `void sub_${address.slice(2)}()\n{\n}`,
      assembly: [`${address}: push    rbp`, "0x1018: retn"],
      callers: [{ address: "0x9000", name: "caller_a", body: {} }],
      callees: [
        { address: "0x2000", name: "ns::helper(int32_t value)" },
        { address: "0x2800", name: "sub_2800" },
      ],
      unresolved_calls: [
        {
          address: "0x1008",
          reason: "The target 0x4000 is not an analyzed function.",
        },
        {
          address: "0x100c",
          reason: "Binary Ninja reported no target address for this call site.",
        },
      ],
      outgoing_references: [
        {
          source_address: "0x1004",
          target_address: "0x2000",
          target_procedure: { address: "0x2000" },
        },
        {
          source_address: "0x1008",
          target_address: "0x4000",
          target_procedure: null,
        },
        {
          source_address: "0x1000",
          target_address: "0x3000",
          target_procedure: null,
        },
      ],
    },
  });

const workspace = async () => {
  const root = await createTestTempDirectory("rea-binja-lane-");
  const jsonDir = join(root, "json");
  const codeDir = join(root, "code");
  const calls: BinjaFetchRequest[] = [];
  const replies = new Map<string, string | Error>();
  const lane = new BinjaFetchLane({
    jsonDir,
    codeDir,
    run: async (request) => {
      calls.push(request);
      const reply =
        replies.get(request.address) ??
        (request.full ? dossier(request.address) : decompiled(request.address));
      if (reply instanceof Error) throw reply;
      return reply;
    },
  });
  return { root, jsonDir, codeDir, calls, replies, lane };
};
const plain = (address: string): BinjaFetchRequest => ({
  address,
  full: false,
});
const full = (address: string): BinjaFetchRequest => ({ address, full: true });

describe("fetch lane evidence files", () => {
  it("saves the envelope verbatim and the pseudocode beside it", async () => {
    const { lane, jsonDir, codeDir } = await workspace();
    expect(lane.saved(plain("0x1000"))).toBe(false);
    await lane.fetch(plain("0x1000"));
    expect(await readFile(join(jsonDir, "decompile-1000.json"), "utf8")).toBe(
      decompiled("0x1000"),
    );
    expect(await readFile(join(codeDir, "0x1000-REA.c"), "utf8")).toBe(
      "int64_t sub_1000()\n{\n    return 0;\n}",
    );
    expect(lane.saved(plain("0x1000"))).toBe(true);
    // A dossier is a separate request and is not satisfied by pseudocode alone.
    expect(lane.saved(full("0x1000"))).toBe(false);
  });

  it("saves assembly and call edges for a full request", async () => {
    const { lane, jsonDir, codeDir } = await workspace();
    await lane.fetch(full("0x1000"));
    expect((await readdir(jsonDir)).sort()).toEqual(["function-1000.json"]);
    expect(await readFile(join(codeDir, "0x1000-REA.asm"), "utf8")).toBe(
      "0x1000: push    rbp\n0x1018: retn\n",
    );
    expect(await readFile(join(codeDir, "0x1000-REA.calls.txt"), "utf8")).toBe(
      "caller 0x9000 caller_a\ncallee 0x2000 ns::helper(int32_t value)\ncallee 0x2800 sub_2800\ncallee 0x4000 0x4000\n",
    );
    expect(lane.saved(full("0x1000"))).toBe(true);
    expect(lane.saved(plain("0x1000"))).toBe(true);
  });

  it("never overwrites saved evidence: a new read gets a new envelope name", async () => {
    const { lane, jsonDir, codeDir, replies } = await workspace();
    await lane.fetch(plain("0x1000"));
    replies.set("0x1000", decompiled("0x1000").replace("return 0", "return 1"));
    await lane.fetch(plain("0x1000"));
    expect((await readdir(jsonDir)).sort()).toEqual([
      "decompile-1000.2.json",
      "decompile-1000.json",
    ]);
    expect(await readFile(join(jsonDir, "decompile-1000.json"), "utf8")).toBe(
      decompiled("0x1000"),
    );
    expect(await readFile(join(codeDir, "0x1000-REA.c"), "utf8")).toContain(
      "return 0;",
    );
    // A later dossier adds its files and keeps the pseudocode already saved.
    replies.delete("0x1000");
    await lane.fetch(full("0x1000"));
    expect(await readFile(join(codeDir, "0x1000-REA.c"), "utf8")).toContain(
      "return 0;",
    );
    expect((await readdir(codeDir)).sort()).toEqual([
      "0x1000-REA.asm",
      "0x1000-REA.c",
      "0x1000-REA.calls.txt",
    ]);
  });

  it("recognizes files saved under another label as already fetched", async () => {
    const { lane, codeDir } = await workspace();
    await mkdir(codeDir, { recursive: true });
    await writeFile(join(codeDir, "0x1000-offline.c"), "saved earlier");
    await writeFile(join(codeDir, "0x10000-REA.c"), "a different address");
    expect(lane.saved(plain("0x1000"))).toBe(true);
    expect(lane.saved(plain("0x100"))).toBe(false);
    expect(lane.saved(full("0x1000"))).toBe(false);
  });

  it.each([
    [
      "an analysis failure",
      '{"error":"Analysis failed","code":"execution_failure"}',
      "rea reported",
    ],
    ["text that is not JSON", "Segmentation fault", "Unexpected token"],
    [
      "an envelope without pseudocode",
      '{"provider":{"id":"binja"},"normalized_result":"  \\n"}',
      "no pseudocode",
    ],
    [
      "a dossier answering a plain request",
      dossier("0x1000"),
      "does not answer this request",
    ],
    [
      "a failed call",
      new BinjaFetchError("rea timed out after 900 s"),
      "timed out",
    ],
  ])(
    "leaves an error marker and no evidence for %s",
    async (_label, reply, reason) => {
      const { lane, jsonDir, codeDir, replies } = await workspace();
      replies.set("0x1000", reply);
      await expect(lane.fetch(plain("0x1000"))).rejects.toThrow(
        BinjaFetchError,
      );
      expect(await readdir(jsonDir)).toEqual(["decompile-1000.err"]);
      expect(
        await readFile(join(jsonDir, "decompile-1000.err"), "utf8"),
      ).toContain(reason);
      expect(await readdir(codeDir)).toEqual([]);
      expect(lane.saved(plain("0x1000"))).toBe(false);
    },
  );
});

const clock = () => {
  let time = 0;
  const sleeps: number[] = [];
  return {
    now: () => time,
    sleep: async (ms: number) => {
      sleeps.push(ms);
      time += ms;
    },
    sleeps,
  };
};

describe("fetch lane run", () => {
  it("reads the queue file and every request file, skipping what is saved", async () => {
    const { root, lane, calls } = await workspace();
    const requests = join(root, "requests");
    await mkdir(requests);
    await writeFile(join(root, "queue.txt"), "0x1000\nfull 0x2000\n");
    await writeFile(join(requests, "b-reader.txt"), "0x3000 # second file\n");
    await writeFile(join(requests, "a-reader.txt"), "full 0x1000\n0x4000\n");
    await writeFile(
      join(requests, "notes.md"),
      "0x5000 is not a request file\n",
    );
    const readQueue = () => readFetchQueue(join(root, "queue.txt"), requests);
    expect(readQueue()).toEqual([
      plain("0x4000"),
      plain("0x3000"),
      full("0x1000"),
      full("0x2000"),
    ]);
    const first = await runBinjaFetchLane({ lane, readQueue, watchMs: 0 });
    expect(first).toEqual({
      status: "idle",
      fetched: ["0x4000", "0x3000", "0x1000", "0x2000"],
      failed: [],
    });
    expect(calls).toHaveLength(4);
    const again = await runBinjaFetchLane({ lane, readQueue, watchMs: 0 });
    expect(again.fetched).toEqual([]);
    expect(calls).toHaveLength(4);
    expect(readFetchQueue(undefined, join(root, "absent"))).toEqual([]);
  });

  it("re-reads the queue before every call so a cheap request overtakes a dossier", async () => {
    const { lane, calls } = await workspace();
    const queue = [full("0x1000"), full("0x2000")];
    const outcome = await runBinjaFetchLane({
      lane,
      watchMs: 0,
      readQueue: () => {
        if (calls.length === 1 && queue.length === 2)
          queue.unshift(plain("0x3000"));
        return queue;
      },
    });
    expect(outcome.fetched).toEqual(["0x1000", "0x3000", "0x2000"]);
  });

  it("never runs two analysis calls at once", async () => {
    const root = await createTestTempDirectory("rea-binja-lane-");
    let inFlight = 0;
    let most = 0;
    const lane = new BinjaFetchLane({
      jsonDir: join(root, "json"),
      codeDir: join(root, "code"),
      run: async ({ address }) => {
        inFlight += 1;
        most = Math.max(most, inFlight);
        await new Promise((resolve) => setImmediate(resolve));
        inFlight -= 1;
        return decompiled(address);
      },
    });
    await runBinjaFetchLane({
      lane,
      watchMs: 0,
      readQueue: () => ["0x1000", "0x2000", "0x3000"].map(plain),
    });
    expect(most).toBe(1);
  });
});

describe("fetch lane limits", () => {
  it("stops after consecutive failures instead of hammering a wedged backend", async () => {
    const { lane, replies, calls } = await workspace();
    for (const address of ["0x2000", "0x3000", "0x4000", "0x5000"])
      replies.set(address, new BinjaFetchError("active view changed"));
    const outcome = await runBinjaFetchLane({
      lane,
      watchMs: 0,
      readQueue: () =>
        ["0x1000", "0x2000", "0x3000", "0x4000", "0x5000", "0x6000"].map(plain),
    });
    expect(outcome).toEqual({
      status: "stopped",
      fetched: ["0x1000"],
      failed: ["0x2000", "0x3000", "0x4000"],
    });
    expect(calls.map(({ address }) => address)).toEqual([
      "0x1000",
      "0x2000",
      "0x3000",
      "0x4000",
    ]);
  });

  it("resets the failure streak on success and does not retry a failed address", async () => {
    const { lane, replies, calls } = await workspace();
    for (const address of ["0x1000", "0x3000", "0x5000"])
      replies.set(address, new BinjaFetchError("decompilation failed"));
    const outcome = await runBinjaFetchLane({
      lane,
      watchMs: 0,
      maxConsecutiveFailures: 2,
      readQueue: () =>
        ["0x1000", "0x2000", "0x3000", "0x4000", "0x5000"].map(plain),
    });
    expect(outcome).toEqual({
      status: "idle",
      fetched: ["0x2000", "0x4000"],
      failed: ["0x1000", "0x3000", "0x5000"],
    });
    expect(calls).toHaveLength(5);
  });

  it("waits a bounded time for new requests, then ends idle", async () => {
    const { lane } = await workspace();
    const time = clock();
    const queue: BinjaFetchRequest[] = [];
    const outcome = await runBinjaFetchLane({
      lane,
      watchMs: 60_000,
      pollMs: 5000,
      now: time.now,
      sleep: async (ms) => {
        await time.sleep(ms);
        if (time.now() === 20_000) queue.push(plain("0x1000"));
      },
      readQueue: () => queue,
    });
    expect(outcome.fetched).toEqual(["0x1000"]);
    // 4 polls before the request arrives, then a full idle window after it.
    expect(time.sleeps).toHaveLength(4 + 12);
    expect(time.now()).toBe(80_000);
  });

  it("stops between calls when asked to", async () => {
    const { lane, calls } = await workspace();
    const stop = new AbortController();
    const outcome = await runBinjaFetchLane({
      lane,
      watchMs: 3_600_000,
      signal: stop.signal,
      readQueue: () => {
        // Asked during the second iteration: that call still completes.
        if (calls.length === 1) stop.abort();
        return ["0x1000", "0x2000", "0x3000"].map(plain);
      },
    });
    expect(outcome).toEqual({
      status: "idle",
      fetched: ["0x1000", "0x2000"],
      failed: [],
    });
  });
});

describe("one-caller lock", () => {
  it("refuses a second holder and admits one after release", async () => {
    const root = await createTestTempDirectory("rea-binja-lock-");
    const path = join(root, "nested", "fetch.lock");
    const first = acquireBinjaLock(path);
    expect(() => acquireBinjaLock(path)).toThrow(BinjaLockHeldError);
    first.release();
    first.release();
    const second = acquireBinjaLock(path);
    second.release();
  });

  it("accepts an existing empty lock file", async () => {
    const root = await createTestTempDirectory("rea-binja-lock-");
    const path = join(root, "fetch.lock");
    await writeFile(path, "");
    const lock = acquireBinjaLock(path);
    expect(() => acquireBinjaLock(path)).toThrow(/one caller at a time/u);
    lock.release();
  });
});
