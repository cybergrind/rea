import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { createBinjaMcpConnection } from "../../../../src/binja/BinjaMcpConnection.js";
import { BinjaProvider } from "../../../../src/binja/BinjaProvider.js";
import {
  BINJA_OPERATIONS,
  BINJA_READ_ONLY_TOOLS,
  BINJA_UNSUPPORTED_OPERATIONS,
} from "../../../../src/binja/BinjaProviderCapabilities.js";
import { parseConfig } from "../../../../src/config/parseConfig.js";
import {
  BinjaProducerFixture,
  binjaTarget,
  materializeBinjaTarget,
} from "../../../fixtures/binjaMcp.js";

const configured = (url = "http://127.0.0.1:24642/mcp") => {
  const config = parseConfig({ REA_BINJA_MCP_URL: url });
  if (!config.ok) throw config.error;
  return config.value;
};

describe("Binary Ninja provider candidate", () => {
  it("is unavailable and inert without an explicit endpoint", async () => {
    const config = parseConfig({});
    if (!config.ok) throw config.error;
    const provider = new BinjaProvider(config.value, () => {
      throw new Error("An unconfigured provider must not create a connection");
    });
    expect(provider.inspectAvailability()).toMatchObject({
      status: "unavailable",
      code: "not_configured",
      diagnostics: { configured: false, live_connection_probed: false },
    });
    const profile = await provider.resolveAnalysisProfile(binjaTarget());
    if (profile.ok) throw new Error("An unconfigured provider has no profile");
    expect(profile.error._tag).toBe("ConfigurationError");
    const client = provider.createClient(binjaTarget());
    const execution = await client.execute("list_documents", {});
    if (execution.ok)
      throw new Error("An unconfigured provider cannot execute");
    expect(execution.error.message).toContain("REA_BINJA_MCP_URL");
    const closed = await client.close();
    if (!closed.ok) throw closed.error;
  });

  it("discovers without connecting and commits adapter, not engine, identity", async () => {
    let created = 0;
    const provider = new BinjaProvider(configured(), () => {
      created += 1;
      throw new Error("Discovery must not create a connection");
    });
    expect(provider.identity()).toEqual({
      id: "binja",
      name: "Binary Ninja MCP adapter",
      version: "1",
    });
    expect(provider.inspectAvailability()).toMatchObject({
      status: "available",
      diagnostics: { mode: "attached", live_connection_probed: false },
    });
    const resolution = await provider.resolveAnalysisProfile(binjaTarget());
    if (!resolution.ok) throw resolution.error;
    expect(resolution.value.profile.parameters).toEqual({
      version_scope: "rea-binja-adapter",
      engine_version: null,
      mode: "attached",
      endpoint: "http://127.0.0.1:24642/mcp",
      database_revision: null,
      cache_policy: "live",
    });
    const cancelled = new AbortController();
    cancelled.abort();
    const refused = await provider.resolveAnalysisProfile(binjaTarget(), {
      signal: cancelled.signal,
    });
    if (refused.ok) throw new Error("A cancelled resolution must not succeed");
    expect(refused.error._tag).toBe("AnalysisCancelledError");
    expect(created).toBe(0);
  });

  it("advertises served operations as live reads and names each refusal", () => {
    const capabilities = new BinjaProvider(configured()).capabilities();
    expect(capabilities.map(({ operation }) => operation).sort()).toEqual(
      [
        ...BINJA_OPERATIONS,
        ...BINJA_UNSUPPORTED_OPERATIONS.map(([operation]) => operation),
      ].sort(),
    );
    for (const capability of capabilities) {
      expect(capability.provider.id).toBe("binja");
      expect(capability.cachePolicy).toBe("live");
      expect(capability.effects).toMatchObject({
        mutatesArtifact: false,
        launchesProcess: false,
        mayShowUi: false,
        mayWriteFilesystem: false,
      });
    }
    const refused = new Map(
      capabilities.flatMap(({ operation, available, reason }) =>
        available ? [] : [[operation, reason] as const],
      ),
    );
    expect([...refused.keys()].sort()).toEqual(
      BINJA_UNSUPPORTED_OPERATIONS.map(([operation]) => operation).sort(),
    );
    expect(refused.get("set_comment")).toContain("read-only");
    expect(refused.get("inspect_native_data_type")).toContain("Not mapped");
  });

  it("admits executables other than MIPS and refuses analysis databases", () => {
    const provider = new BinjaProvider(configured());
    expect(provider.inspectTargetSupport(binjaTarget()).status).toBe(
      "supported",
    );
    expect(
      provider.inspectTargetSupport({
        path: "/fixtures/target.bndb",
        sha256: "0".repeat(64),
        kind: "database",
        format: "analysis-database",
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_kind_unsupported",
    });
    expect(
      provider.inspectTargetSupport({
        path: "/fixtures/target.elf",
        sha256: "0".repeat(64),
        kind: "executable",
        format: "elf",
        architecture: "mips",
        availableArchitectures: ["mips"],
        mips: { elfClass: 32, byteOrder: "big", type: 2, flags: 0 },
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
    });
  });

  it("creates one session per client on the configured endpoint", async () => {
    const { target } = await materializeBinjaTarget();
    const producers: BinjaProducerFixture[] = [];
    const endpoints: string[] = [];
    const provider = new BinjaProvider(configured(), ({ url }) => {
      endpoints.push(url);
      const producer = new BinjaProducerFixture(target);
      producers.push(producer);
      return producer;
    });
    const client = provider.createClient(target);
    const execution = await client.execute("procedure_address", {
      procedure: "main",
    });
    if (!execution.ok) throw execution.error;
    expect(execution.value.provider.id).toBe("binja");
    expect(execution.value.result).toBe("0x1000");
    expect(endpoints).toEqual(["http://127.0.0.1:24642/mcp"]);
    const closed = await client.close();
    if (!closed.ok) throw closed.error;
    expect(producers.map(({ closes }) => closes)).toEqual([1]);
  });
});

describe("Binary Ninja endpoint transport", () => {
  it("reports an unreachable endpoint as an adapter failure with recovery guidance", async () => {
    const { target } = await materializeBinjaTarget();
    // Port 1 on loopback refuses connections on every supported host.
    const provider = new BinjaProvider(configured("http://127.0.0.1:1/mcp"));
    const client = provider.createClient(target);
    const execution = await client.execute("list_documents", {});
    if (execution.ok) throw new Error("An unreachable endpoint cannot answer");
    expect(execution.error).toMatchObject({
      _tag: "ProviderAdapterError",
      providerId: "binja",
      diagnostics: { recovery: expect.stringContaining("REA_BINJA_MCP_URL") },
    });
    await client.close();
  });

  it("refuses HTTP redirects before sending requests to another endpoint", async () => {
    let followed = false;
    const server = createServer((request, response) => {
      if (request.url === "/redirected") followed = true;
      request.resume();
      response.writeHead(307, { Location: "/redirected" });
      response.end();
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("Expected TCP listener");
    const connection = createBinjaMcpConnection(
      { url: `http://127.0.0.1:${String(address.port)}/mcp`, timeoutMs: 2000 },
      BINJA_READ_ONLY_TOOLS,
    );
    try {
      await expect(connection.connect()).rejects.toThrow();
      expect(followed).toBe(false);
    } finally {
      await connection.close();
      await new Promise<void>((resolve, reject) =>
        server.close((cause) =>
          cause === undefined ? resolve() : reject(cause),
        ),
      );
    }
  });
});
