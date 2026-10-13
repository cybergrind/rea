#!/usr/bin/env node
// Operator tooling: drain queued function addresses through REA's public CLI
// and the read-only `binja` provider, strictly one at a time, onto disk.
// Binary Ninja answers one caller at a time, so this lane holds a lock for its
// whole run and readers work offline on the saved files.
import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs, promisify } from "node:util";

const USAGE = `Usage: node scripts/binja-fetch-lane.mjs --target BINARY --json-dir DIR --code-dir DIR
           [--queue FILE] [--requests DIR] [--watch S] [--timeout S]
           [--max-failures N] [--lock PATH]

  --target        the original binary whose view is active in Binary Ninja
  --queue         queue file: one hex address per line; "full <addr>" asks for the
                  dossier (pseudocode, assembly, callers and callees); # starts a comment
  --requests      directory of further *.txt queue files dropped by readers
  --json-dir      Evidence envelopes (<command>-<addr>.json) and .err markers
  --code-dir      extracted text (0x<addr>-REA.c, .asm, .calls.txt)
  --watch         keep serving new requests until idle this many seconds (default 0)
  --timeout       deadline of one analysis call in seconds (default 900)
  --max-failures  stop after this many consecutive failures (default 3)
  --lock          lock file (default REA_BINJA_LOCK, else <json-dir>/fetch.lock)

Requires REA_BINJA_MCP_URL. Saved files are never overwritten and saved
addresses are skipped. Exit codes: 0 idle, 1 failures or stopped, 2 refused.`;

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const importBuilt = async (path) => {
  const file = join(packageRoot, "dist", path);
  try {
    await access(file);
  } catch {
    throw new Error(
      `REA's compiled runtime is missing (${file}). Run \`npm ci && npm run build:cached\` in ${packageRoot}.`,
    );
  }
  return import(pathToFileURL(file).href);
};
const log = (line) =>
  console.error(`${new Date().toISOString()} binja-fetch-lane ${line}`);

const main = async () => {
  const { values } = parseArgs({
    options: {
      target: { type: "string" },
      queue: { type: "string" },
      requests: { type: "string" },
      "json-dir": { type: "string" },
      "code-dir": { type: "string" },
      watch: { type: "string", default: "0" },
      timeout: { type: "string", default: "900" },
      "max-failures": { type: "string", default: "3" },
      lock: { type: "string" },
      help: { type: "boolean", default: false },
    },
  });
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  const number = (name, minimum) => {
    const value = Number(values[name]);
    if (!Number.isFinite(value) || value < minimum)
      throw new Error(`--${name} must be a number of at least ${minimum}`);
    return value;
  };
  if (
    values.target === undefined ||
    values["json-dir"] === undefined ||
    values["code-dir"] === undefined
  )
    throw new Error(
      `--target, --json-dir and --code-dir are required\n\n${USAGE}`,
    );
  if (values.queue === undefined && values.requests === undefined)
    throw new Error("Give --queue, --requests, or both.");
  if (process.env.REA_BINJA_MCP_URL === undefined)
    throw new Error(
      "Set REA_BINJA_MCP_URL to the loopback MCP endpoint of a running Binary Ninja.",
    );
  const target = resolve(values.target);
  const jsonDir = resolve(values["json-dir"]);
  const timeout = number("timeout", 1) * 1000;
  const [lane, { acquireBinjaLock }] = await Promise.all([
    importBuilt("binja/operator/BinjaFetchLane.js"),
    importBuilt("binja/operator/BinjaExclusiveLock.js"),
  ]);
  const run = async (request) => {
    try {
      const { stdout } = await promisify(execFile)(
        process.execPath,
        [
          join(packageRoot, "scripts", "rea.mjs"),
          lane.fetchCommand(request),
          target,
          request.address,
          "--provider",
          "binja",
          "--format",
          "json",
        ],
        { timeout, maxBuffer: 512 * 1024 * 1024, killSignal: "SIGTERM" },
      );
      return stdout;
    } catch (cause) {
      const stdout = typeof cause?.stdout === "string" ? cause.stdout : "";
      // REA reports an analysis failure as JSON on stdout with exit code 0 or 1.
      if (stdout.trim() !== "" && cause?.killed !== true) return stdout;
      throw new lane.BinjaFetchError(
        cause?.killed === true
          ? `rea timed out after ${timeout / 1000} s`
          : `rea failed: ${String(cause?.stderr ?? cause?.message ?? cause)
              .trim()
              .slice(-2000)}`,
      );
    }
  };
  const lock = acquireBinjaLock(
    resolve(
      values.lock ?? process.env.REA_BINJA_LOCK ?? join(jsonDir, "fetch.lock"),
    ),
  );
  const stop = new AbortController();
  for (const signal of ["SIGINT", "SIGTERM"])
    process.once(signal, () => {
      log(`${signal}: stopping after the current call`);
      stop.abort();
    });
  try {
    const outcome = await lane.runBinjaFetchLane({
      lane: new lane.BinjaFetchLane({
        run,
        jsonDir,
        codeDir: resolve(values["code-dir"]),
        log,
      }),
      readQueue: () =>
        lane.readFetchQueue(
          values.queue === undefined ? undefined : resolve(values.queue),
          values.requests === undefined ? undefined : resolve(values.requests),
        ),
      watchMs: number("watch", 0) * 1000,
      maxConsecutiveFailures: number("max-failures", 1),
      log,
      signal: stop.signal,
    });
    if (outcome.status === "stopped")
      log(
        "stopped after consecutive failures; check Binary Ninja and its active view before restarting",
      );
    log(
      `${outcome.status}; ${outcome.fetched.length} fetched, ${outcome.failed.length} failed`,
    );
    return outcome.status === "stopped" || outcome.failed.length > 0 ? 1 : 0;
  } finally {
    lock.release();
  }
};

try {
  process.exitCode = await main();
} catch (cause) {
  log(cause instanceof Error ? cause.message : String(cause));
  process.exitCode = 2;
}
