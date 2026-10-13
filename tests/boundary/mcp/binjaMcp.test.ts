import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";

import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import { BinjaProvider } from "../../../src/binja/BinjaProvider.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { silentLogger } from "../../../src/logger.js";
import { createServer } from "../../../src/server/createServer.js";
import {
  BinjaProducerFixture,
  materializeBinjaTarget,
} from "../../fixtures/binjaMcp.js";

const connect = async () => {
  const { target } = await materializeBinjaTarget();
  const config = parseConfig({
    REA_BINJA_MCP_URL: "http://127.0.0.1:24642/mcp",
  });
  if (!config.ok) throw config.error;
  const producer = new BinjaProducerFixture(target);
  const session = composeBinarySession(
    new AnalysisProviderRegistry([
      new BinjaProvider(config.value, () => producer),
    ]),
  );
  const server = createServer(
    { kind: "session", session },
    { logger: silentLogger },
  );
  const client = new Client({ name: "binja-workflow", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const result = await client.callTool({ name, arguments: args });
    const text = (result.content ?? [])
      .map((block) => (block.type === "text" ? block.text : ""))
      .join("");
    return { isError: result.isError === true, text };
  };
  return { target, producer, call };
};

const json = (text: string): unknown => JSON.parse(text);

it("opens, analyzes, and closes a Binary Ninja target through MCP tools", async () => {
  const { target, producer, call } = await connect();
  const opened = await call("open_binary", {
    path: target.path,
    provider_id: "binja",
  });
  expect(opened.isError).toBe(false);
  // Opening binds the provider; the engine is first contacted by analysis.
  expect(producer.connects).toBe(0);
  const status = await call("binary_session");
  expect(json(status.text)).toMatchObject({
    result: {
      open: true,
      analysis_provider_binding: {
        provider: { id: "binja" },
        selection_source: "request",
      },
    },
  });

  const decompiled = await call("procedure_pseudo_code", { procedure: "main" });
  expect(decompiled.isError).toBe(false);
  const evidence = parseEvidence(json(decompiled.text));
  expect(evidence.provider).toEqual({
    id: "binja",
    name: "Binary Ninja MCP adapter",
    version: "1",
  });
  expect(evidence.normalized_result).toBe("  main\n\n{\n    return 42;\n}");
  expect(evidence.limitations.join(" ")).toContain("no input hash");

  // A composed workflow reaches the provider through its primitives only.
  const overview = await call("binary_overview");
  expect(overview.isError).toBe(false);
  expect(parseEvidence(json(overview.text)).normalized_result).toMatchObject({
    document: target.path,
    segment_count: 2,
    procedure_count: 2,
    string_count: 3,
  });
  expect(producer.maxInFlight).toBe(1);

  const closed = await call("close_binary");
  expect(closed.isError).toBe(false);
  expect(producer.closes).toBe(1);
  expect(
    producer.calls.filter(({ name }) =>
      /save|close|open_item_open/u.test(name),
    ),
  ).toEqual([]);
});

it("reports a refused operation and a missing procedure through the MCP boundary", async () => {
  const { target, producer, call } = await connect();
  await call("open_binary", { path: target.path, provider_id: "binja" });
  const refused = await call("set_comment", {
    address: "0x1000",
    comment: "analyst note",
  });
  expect(refused.isError).toBe(true);
  expect(json(refused.text)).toMatchObject({
    error: {
      code: "capability_unavailable",
      details: {
        provider_id: "binja",
        operation: "set_comment",
        reason: expect.stringContaining("read-only"),
      },
    },
  });
  expect(producer.connects).toBe(0);
  const missing = await call("procedure_pseudo_code", { procedure: "absent" });
  expect(missing.isError).toBe(true);
  expect(missing.text).toContain("No analyzed function is named absent");
});

it("fails analysis with recovery guidance when the active view is another item", async () => {
  const { target, producer, call } = await connect();
  await call("open_binary", { path: target.path, provider_id: "binja" });
  producer.rawBytes = 4096;
  const mismatched = await call("procedure_pseudo_code", { procedure: "main" });
  expect(mismatched.isError).toBe(true);
  expect(mismatched.text).toContain("does not hold the selected target");
  expect(
    producer.calls.filter(({ name }) => name.startsWith("bn_function_")),
  ).toEqual([]);
});
