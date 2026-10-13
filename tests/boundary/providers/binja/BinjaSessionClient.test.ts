import { sep } from "node:path";
import { describe, expect, it } from "vitest";
import type { AnalysisOperation } from "../../../../src/application/AnalysisProvider.js";
import {
  BINJA_READ_ONLY_TOOLS,
  BINJA_UNSUPPORTED_OPERATIONS,
} from "../../../../src/binja/BinjaProviderCapabilities.js";
import { BinjaSessionClient } from "../../../../src/binja/BinjaSessionClient.js";
import { BinjaToolError } from "../../../../src/binja/BinjaMcpConnection.js";
import type { JsonValue } from "../../../../src/domain/jsonValue.js";
import {
  BinjaProducerFixture,
  materializeBinjaTarget,
} from "../../../fixtures/binjaMcp.js";

const fixture = async () => {
  const { target } = await materializeBinjaTarget();
  const producer = new BinjaProducerFixture(target);
  return { target, producer, client: new BinjaSessionClient(target, producer) };
};
const run = async (
  client: BinjaSessionClient,
  operation: AnalysisOperation,
  parameters: Readonly<Record<string, JsonValue>> = {},
) => {
  const execution = await client.execute(operation, parameters);
  if (!execution.ok) throw execution.error;
  return execution.value;
};
const failure = async (
  client: BinjaSessionClient,
  operation: AnalysisOperation,
  parameters: Readonly<Record<string, JsonValue>> = {},
) => {
  const execution = await client.execute(operation, parameters);
  if (execution.ok) throw new Error(`${operation} unexpectedly succeeded`);
  return execution.error;
};

describe("attached Binary Ninja session", () => {
  it("labels an observation as binja with its binding, raw requests, and locations", async () => {
    const { client, target } = await fixture();
    const execution = await run(client, "procedure_pseudo_code", {
      procedure: "main",
    });
    expect(execution.provider).toEqual({
      id: "binja",
      name: "Binary Ninja MCP adapter",
      version: "1",
    });
    expect(execution.result).toBe("  main\n\n{\n    return 42;\n}");
    expect(execution.locations).toEqual([
      { kind: "artifact-path", path: target.path },
      { kind: "address", address: "0x1000" },
    ]);
    expect(execution.rawResult).toMatchObject({
      upstream: { name: "binaryninja_ui_mcp", version: "0.1.0" },
      view_before: { binary_view: "view_1", image_base: "0x1000" },
      view_after: { binary_view: "view_1", analysis_state: "IdleState" },
      observations: [
        { tool: "bn_function_list", arguments: { query: "main" } },
        { tool: "bn_function_info", arguments: { function: "0x1000" } },
        { tool: "bn_function_decompile" },
      ],
    });
    expect(execution.limitations.join(" ")).toContain(
      "Binary Ninja reports no input hash",
    );
    const health = await run(client, "health");
    expect(health.result).toMatchObject({
      ready: true,
      view: { open_item_path: `${target.path}.bndb` },
    });
    await client.close();
  });

  it("never calls a tool outside the read-only set and only releases its connection on close", async () => {
    const { client, producer } = await fixture();
    await run(client, "analyze_function", { procedure: "main" });
    await run(client, "list_segments");
    await run(client, "search_strings", { pattern: "needle" });
    await run(client, "xrefs", { address: "0x2000" });
    const before = producer.calls.length;
    const closed = await client.close();
    if (!closed.ok) throw closed.error;
    expect(producer.closes).toBe(1);
    expect(producer.calls).toHaveLength(before);
    expect(
      producer.calls.filter(({ name }) => !BINJA_READ_ONLY_TOOLS.has(name)),
    ).toEqual([]);
    expect((await failure(client, "list_documents")).message).toContain(
      "closing or closed",
    );
  });

  it("closes without connecting when nothing was requested", async () => {
    const { client, producer } = await fixture();
    const closed = await client.close();
    if (!closed.ok) throw closed.error;
    expect(producer.connects).toBe(0);
    expect(producer.closes).toBe(0);
  });

  it.each(BINJA_UNSUPPORTED_OPERATIONS)(
    "refuses %s with its stated reason before connecting",
    async (operation, reason) => {
      const { client, producer } = await fixture();
      const error = await failure(client, operation, {
        address: "0x1000",
        procedure: "main",
      });
      expect(error._tag).toBe("AnalysisCapabilityUnavailableError");
      expect(error.message).toContain(reason);
      expect(producer.connects).toBe(0);
    },
  );

  it("requires every read-only tool of the adapter before the first request", async () => {
    const { client, producer } = await fixture();
    producer.tools = producer.tools.filter((name) => name !== "bn_data_at");
    const error = await failure(client, "list_documents");
    expect(error).toMatchObject({
      _tag: "ProviderAdapterError",
      userMessage: expect.stringContaining(
        "missing tools this adapter requires: bn_data_at",
      ),
      diagnostics: { missing_tools: ["bn_data_at"] },
    });
    expect(producer.calls).toEqual([]);
    await client.close();
  });
});

describe("attached Binary Ninja session failures and ordering", () => {
  it("serializes concurrent requests because Binary Ninja serves one caller", async () => {
    const { client, producer } = await fixture();
    const results = await Promise.all([
      client.execute("list_procedures", {}),
      client.execute("list_strings", {}),
      client.execute("list_segments", {}),
      client.execute("analyze_function", { procedure: "main" }),
    ]);
    for (const result of results) if (!result.ok) throw result.error;
    expect(producer.maxInFlight).toBe(1);
    expect(producer.connects).toBe(1);
    await client.close();
  });

  it("fails a request during which the active view changes", async () => {
    const { client, producer } = await fixture();
    producer.beforeCall = async (name) => {
      if (name === "bn_function_decompile") producer.activeViews = ["view_2"];
    };
    const changed = {
      _tag: "ProviderAdapterError",
      operation: "target_binding",
      diagnostics: {
        reason: expect.stringContaining("changed during the REA session"),
      },
    };
    expect(
      await failure(client, "procedure_pseudo_code", { procedure: "main" }),
    ).toMatchObject(changed);
    producer.beforeCall = undefined;
    expect(
      await failure(client, "procedure_address", { procedure: "main" }),
    ).toMatchObject(changed);
    producer.activeViews = ["view_1"];
    expect(
      (await run(client, "procedure_address", { procedure: "main" })).result,
    ).toBe("0x1000");
    await client.close();
  });

  it("accepts only the bound document", async () => {
    const { client, target } = await fixture();
    const equivalent =
      process.platform === "win32"
        ? target.path.toLowerCase().replaceAll("\\", "/")
        : target.path.split(sep).join(`${sep}.${sep}`);
    expect(
      (
        await run(client, "procedure_address", {
          procedure: "main",
          document: equivalent,
        })
      ).result,
    ).toBe("0x1000");
    const other = await failure(client, "procedure_address", {
      procedure: "main",
      document: "/other/binary",
    });
    expect(other).toMatchObject({
      _tag: "AnalysisInputError",
      issues: [{ path: ["document"], expected: target.path }],
    });
    await client.close();
  });

  it("validates input before connecting", async () => {
    const { client, producer } = await fixture();
    for (const operation of ["xrefs", "comment", "address_name"] as const)
      expect((await failure(client, operation))._tag).toBe(
        "AnalysisInputError",
      );
    expect(producer.connects).toBe(0);
  });
});

describe("attached Binary Ninja session cancellation and errors", () => {
  it("honours cancellation before and during a request", async () => {
    const { client, producer } = await fixture();
    const early = new AbortController();
    early.abort();
    const refused = await client.execute(
      "list_documents",
      {},
      { signal: early.signal },
    );
    if (refused.ok) throw new Error("A cancelled request must not succeed");
    expect(refused.error._tag).toBe("AnalysisCancelledError");
    expect(producer.connects).toBe(0);
    const controller = new AbortController();
    producer.beforeCall = async (name) => {
      if (name === "bn_function_decompile") controller.abort();
    };
    const cancelled = await client.execute(
      "procedure_pseudo_code",
      { procedure: "main" },
      { signal: controller.signal },
    );
    if (cancelled.ok) throw new Error("A cancelled request must not succeed");
    expect(cancelled.error._tag).toBe("AnalysisCancelledError");
    expect(producer.calls.at(-1)?.name).toBe("bn_function_decompile");
    await client.close();
  });

  it("preserves an engine refusal and types malformed or unreachable producers", async () => {
    const { client, producer } = await fixture();
    producer.overrideCall = (name) => {
      if (name === "bn_function_decompile")
        throw new BinjaToolError(name, "internal_error", "decompiler crashed");
      return undefined;
    };
    expect(
      await failure(client, "procedure_pseudo_code", { procedure: "main" }),
    ).toMatchObject({
      _tag: "ProviderAdapterError",
      userMessage:
        "Binary Ninja refused bn_function_decompile (internal_error): decompiler crashed",
      diagnostics: {
        reason: "decompiler crashed",
        upstream_tool: "bn_function_decompile",
        upstream_code: "internal_error",
      },
    });
    producer.overrideCall = (name) =>
      name === "bn_comment_get" ? { unexpected: true } : undefined;
    const malformed = await failure(client, "comment", { address: "0x1000" });
    expect(malformed._tag).toBe("AnalysisOutputError");
    expect(malformed.message).toContain("text:");
    producer.overrideCall = (name) => {
      if (name === "bn_segment_list")
        throw new Error("connect ECONNREFUSED 127.0.0.1:24642");
      return undefined;
    };
    const unreachable = await failure(client, "list_segments");
    expect(unreachable).toMatchObject({
      _tag: "ProviderAdapterError",
      providerId: "binja",
      diagnostics: {
        reason: "connect ECONNREFUSED 127.0.0.1:24642",
        recovery: expect.stringContaining("REA_BINJA_MCP_URL"),
      },
    });
    await client.close();
  });

  it("reports a failed connection release instead of claiming a clean close", async () => {
    const { client, producer } = await fixture();
    await run(client, "list_documents");
    producer.close = async () => {
      throw new Error("socket hang up");
    };
    const closed = await client.close();
    if (closed.ok) throw new Error("A failed release must be reported");
    expect(closed.error).toMatchObject({
      _tag: "ProviderAdapterError",
      diagnostics: { reason: "socket hang up" },
    });
  });
});
