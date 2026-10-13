#!/usr/bin/env node
import { requireMcpToolError } from "./lib/mcp-verifier-results.mjs";

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs, promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

// Real-provider lane for the read-only `binja` adapter. It needs a running
// Binary Ninja whose active view holds --target. It opens, closes, saves and
// activates nothing, and by default skips whole-database inventories, which
// are very large on big binaries (pass --inventories to include them).
const { values } = parseArgs({
  options: {
    target: { type: "string" },
    procedure: { type: "string" },
    inventories: { type: "boolean", default: false },
    "package-root": { type: "string" },
    report: { type: "string" },
  },
});
if (
  values.target === undefined ||
  values.procedure === undefined ||
  process.env.REA_BINJA_MCP_URL === undefined
)
  throw new Error(
    "Binary Ninja verification requires --target, --procedure and REA_BINJA_MCP_URL; see docs/binja-provider.md. No toolchain is installed or started by this lane.",
  );
const packageRoot = resolve(
  values["package-root"] ?? fileURLToPath(new URL("..", import.meta.url)),
);
const target = resolve(values.target);
const entry = join(packageRoot, "scripts", "rea.mjs");
const importBuilt = (path) =>
  import(pathToFileURL(join(packageRoot, "dist", path)).href);
const [
  { toolContract },
  { evidenceSchema },
  { functionDossierSchema },
  { createBinjaMcpConnection },
  { BINJA_READ_ONLY_TOOLS },
] = await Promise.all([
  importBuilt("contracts/toolContracts.js"),
  importBuilt("domain/evidence.js"),
  importBuilt("domain/hopperValues.js"),
  importBuilt("binja/BinjaMcpConnection.js"),
  importBuilt("binja/BinjaProviderCapabilities.js"),
]);
const timeoutMs = Number(process.env.REA_BINJA_MCP_TIMEOUT_MS ?? 900_000);
const environment = Object.fromEntries(
  Object.entries({
    ...process.env,
    REA_ANALYSIS_PROVIDER: "binja",
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => value !== undefined),
);
const report = { passed: false, checks: [], observations: [] };
let phase = "target admission";
const digest = async () => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(target)) hash.update(chunk);
  return hash.digest("hex");
};
/** Read the GUI state this lane must leave exactly as it found it. */
const guiState = async () => {
  const upstream = createBinjaMcpConnection(
    { url: process.env.REA_BINJA_MCP_URL, timeoutMs },
    BINJA_READ_ONLY_TOOLS,
  );
  try {
    await upstream.connect();
    // Sequential on purpose: Binary Ninja answers one caller at a time.
    const items = await upstream.call("bn_open_item_list", { limit: 1000 });
    const views = await upstream.call("bn_binary_view_list", { limit: 1000 });
    return { items, views };
  } finally {
    await upstream.close();
  }
};
const observe = (input) => {
  const evidence = evidenceSchema.parse(input);
  assert.equal(evidence.provider.id, "binja");
  assert.equal(evidence.provider.version, "1");
  assert.equal(evidence.analysis_profile.parameters.cache_policy, "live");
  assert.equal(evidence.analysis_profile.parameters.engine_version, null);
  assert.ok(evidence.limitations.length > 0);
  assert.ok(
    evidence.locations.some((location) => location.kind === "artifact-path"),
  );
  for (const observation of evidence.raw_result.observations)
    assert.ok(BINJA_READ_ONLY_TOOLS.has(observation.tool));
  report.observations.push(evidence);
  return evidence.normalized_result;
};
const cli = async () => {
  phase = "production CLI function analysis";
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entry,
      "function",
      target,
      values.procedure,
      "--provider",
      "binja",
      "--json",
    ],
    { env: environment, timeout: timeoutMs * 3, maxBuffer: 256 * 1024 * 1024 },
  ).catch((cause) => {
    report.failed_cli = { stdout: cause.stdout, stderr: cause.stderr };
    throw cause;
  });
  const dossier = functionDossierSchema.parse(observe(JSON.parse(stdout)));
  assert.ok(dossier.pseudocode.length > 0);
  assert.ok(dossier.assembly.length > 0);
  assert.equal(dossier.procedure.body.available, true);
  assert.equal(dossier.procedure.body.contains_entry, true);
  report.checks.push("production CLI and complete function Evidence");
  return dossier;
};
const mcp = async (cliDossier) => {
  const client = new Client({ name: "rea-real-binja-verifier", version: "1" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry, "mcp"],
    env: environment,
    stderr: "pipe",
  });
  transport.stderr?.on("data", () => undefined);
  const call = async (name, args) => {
    phase = `production MCP ${name}`;
    const result = await client.callTool(
      { name, arguments: args },
      { timeout: timeoutMs * 2 },
    );
    if (result.isError === true) report.failed_tool_result = result;
    assert.notEqual(result.isError, true);
    return toolContract(name).outputSchema.parse(result.structuredContent);
  };
  let opened = false;
  try {
    await client.connect(transport, { timeout: timeoutMs });
    await call("open_binary", { path: target, provider_id: "binja" });
    opened = true;
    const analyzed = await call("analyze_function", {
      procedure: values.procedure,
    });
    const dossier = functionDossierSchema.parse(observe(analyzed));
    assert.deepEqual(dossier.procedure, cliDossier.procedure);
    assert.equal(dossier.pseudocode, cliDossier.pseudocode);
    assert.deepEqual(dossier.assembly, cliDossier.assembly);
    const entryAddress = dossier.procedure.address;
    const interior = `0x${(BigInt(entryAddress) + 1n).toString(16)}`;
    for (const [name, args] of [
      ["procedure_address", { procedure: dossier.procedure.name }],
      ["procedure_info", { procedure: entryAddress }],
      ["procedure_assembly", { procedure: entryAddress }],
      ["procedure_pseudo_code", { procedure: entryAddress }],
      ["procedure_callees", { procedure: entryAddress }],
      ["procedure_callers", { procedure: entryAddress }],
      ["procedure_references", { procedure: entryAddress }],
      [
        "procedure_references",
        { procedure: entryAddress, direction: "incoming" },
      ],
      ["read_function_instructions", { procedure: entryAddress }],
      ["search_procedures", { pattern: dossier.procedure.name }],
      ["xrefs", { address: entryAddress }],
      ["address_name", { address: entryAddress }],
      ["comment", { address: entryAddress }],
      ["read_bytes", { address: entryAddress, length: 16 }],
      ["address_to_file_offset", { address: entryAddress }],
      ["list_segments", {}],
      ["list_documents", {}],
      ...(values.inventories
        ? [
            ["list_procedures", {}],
            ["list_strings", {}],
            ["list_names", {}],
          ]
        : []),
    ])
      observe(await call(name, args));
    const containing = observe(
      await call("resolve_containing_procedure", { address: interior }),
    );
    if (
      dossier.procedure.body.total_bytes > 1 &&
      dossier.procedure.body.ranges[0]?.start === entryAddress
    )
      assert.equal(containing.procedure?.address, entryAddress);
    const invalid = await client.callTool({
      name: "xrefs",
      arguments: { address: "not-an-address" },
    });
    assert.equal(invalid.isError, true);
    assert.equal(requireMcpToolError(invalid).code, "invalid_request");
    const refused = await client.callTool({
      name: "set_comment",
      arguments: { address: entryAddress, comment: "rea verifier" },
    });
    assert.equal(refused.isError, true);
    assert.equal(requireMcpToolError(refused).code, "capability_unavailable");
    await call("close_binary", {});
    opened = false;
    report.checks.push(
      "one MCP connection, target selection, function and address analysis, invalid input, refused mutation, and close",
    );
    report.checks.push(
      "CLI/MCP function identity, pseudocode, assembly, and raw Evidence parity",
    );
  } finally {
    const completedPhase = phase;
    if (opened) await call("close_binary", {});
    await client.close();
    phase = completedPhase;
  }
};
try {
  const before = await digest();
  phase = "GUI state before";
  const guiBefore = await guiState();
  await mcp(await cli());
  phase = "GUI state after";
  assert.deepEqual(await guiState(), guiBefore);
  report.checks.push(
    "open items, their unsaved-change flags, and the active view are unchanged",
  );
  assert.equal(await digest(), before);
  report.checks.push("original binary unchanged and never executed");
  report.passed = true;
} catch (cause) {
  report.failure = {
    phase,
    message: cause instanceof Error ? cause.message : String(cause),
  };
  process.exitCode = 1;
} finally {
  if (values.report !== undefined)
    await writeFile(
      resolve(values.report),
      `${JSON.stringify(report, null, 2)}\n`,
      { mode: 0o600 },
    );
  console.log(
    JSON.stringify(
      {
        passed: report.passed,
        checks: report.checks,
        ...(report.passed
          ? {}
          : {
              failed_phase: phase,
              detail: "Use --report for private local diagnostics.",
            }),
      },
      null,
      2,
    ),
  );
}
