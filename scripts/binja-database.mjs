#!/usr/bin/env node
// Operator tooling for an attached Binary Ninja: list, open, wait for, and
// save databases. This is NOT part of REA's analysis surface: the `binja`
// provider is read-only, while `open` and `save` here change GUI state. They
// do so only when their subcommand is invoked; nothing closes an item.
import { access } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const USAGE = `Usage: node scripts/binja-database.mjs [--url URL] [--lock PATH] <command>

  list [--root DIR]            saved *.bndb files under DIR (default .) and open items
  open BINARY [--allow-second] open the saved database beside BINARY if one exists,
                               else BINARY itself, and activate its view
  status                       analysis state of the active view (exit 3 unless idle)
  wait [--limit S] [--interval S]
                               poll until idle (default 900 s, every 60 s; exit 3 on limit)
  save ITEM                    save one open item of an idle view; never retried
  call TOOL [JSON] [--mutating]
                               one raw tool call; read-only tools unless --mutating

The endpoint comes from --url or REA_BINJA_MCP_URL. The lock comes from --lock
or REA_BINJA_LOCK; when set, the command runs only while it holds that lock,
so it never overlaps a fetch lane. Exit codes: 0 ok, 2 refused, 3 not idle.`;

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

const main = async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      url: { type: "string" },
      lock: { type: "string" },
      root: { type: "string", default: "." },
      "allow-second": { type: "boolean", default: false },
      limit: { type: "string", default: "900" },
      interval: { type: "string", default: "60" },
      mutating: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });
  const [command, ...rest] = positionals;
  if (values.help || command === undefined) {
    console.log(USAGE);
    return command === undefined && !values.help ? 2 : 0;
  }
  const [
    { binjaMcpUrlSchema },
    { createBinjaMcpConnection },
    { BINJA_READ_ONLY_TOOLS },
    tool,
    { acquireBinjaLock },
  ] = await Promise.all([
    importBuilt("config/binjaMcpEndpoint.js"),
    importBuilt("binja/BinjaMcpConnection.js"),
    importBuilt("binja/BinjaProviderCapabilities.js"),
    importBuilt("binja/operator/BinjaDatabaseTool.js"),
    importBuilt("binja/operator/BinjaExclusiveLock.js"),
  ]);
  const url = binjaMcpUrlSchema.safeParse(
    values.url ?? process.env.REA_BINJA_MCP_URL,
  );
  if (!url.success)
    throw new Error(
      "Set REA_BINJA_MCP_URL (or --url) to the loopback MCP endpoint of a running Binary Ninja.",
    );
  const seconds = (name) => {
    const value = Number(values[name]);
    if (!Number.isFinite(value) || value <= 0)
      throw new Error(`--${name} must be a positive number of seconds`);
    return value * 1000;
  };

  // A raw call reads by default. --mutating widens it to every tool except
  // the ones this tooling never calls; the named subcommands keep a fixed set.
  let authority = tool.BINJA_DATABASE_TOOLS;
  if (command === "call") {
    const name = rest[0];
    if (name === undefined) throw new Error("call requires a tool name");
    if (tool.BINJA_NEVER_CALLED_TOOLS.has(name))
      throw new Error(
        `${name} is never called by this tooling; do it in the GUI.`,
      );
    if (!BINJA_READ_ONLY_TOOLS.has(name) && !values.mutating)
      throw new Error(
        `${name} is not a read-only tool; repeat with --mutating if you mean to change Binary Ninja state.`,
      );
    authority = new Set([name]);
  }

  const lockPath = values.lock ?? process.env.REA_BINJA_LOCK;
  const lock =
    lockPath === undefined ? undefined : acquireBinjaLock(resolve(lockPath));
  if (lock === undefined)
    console.error(
      "binja-database: no --lock or REA_BINJA_LOCK; not coordinated with a fetch lane.",
    );
  const connection = createBinjaMcpConnection(
    { url: url.data, timeoutMs: 120_000 },
    authority,
  );
  try {
    await connection.connect();
    const database = new tool.BinjaDatabaseTool(connection, {
      print: (line) => console.log(line),
    });
    switch (command) {
      case "list":
        return await database.list(resolve(values.root));
      case "open":
        if (rest[0] === undefined)
          throw new Error("open requires a binary path");
        return await database.open(resolve(rest[0]), values["allow-second"]);
      case "status":
        return await database.status();
      case "wait":
        return await database.wait(seconds("limit"), seconds("interval"));
      case "save":
        if (rest[0] === undefined)
          throw new Error("save requires an open item handle");
        console.error(
          `binja-database: saving ${rest[0]}; this blocks Binary Ninja for minutes and is never retried`,
        );
        return await database.save(rest[0]);
      case "call":
        return await database.call(rest[0], JSON.parse(rest[1] ?? "{}"));
      default:
        throw new Error(`Unknown command ${command}\n\n${USAGE}`);
    }
  } finally {
    await connection.close().catch(() => undefined);
    lock?.release();
  }
};

try {
  process.exitCode = await main();
} catch (cause) {
  console.error(
    `binja-database: ${cause instanceof Error ? cause.message : String(cause)}`,
  );
  process.exitCode = 2;
}
