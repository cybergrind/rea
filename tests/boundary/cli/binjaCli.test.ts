import { expect, it } from "vitest";

import { materializeBinjaTarget } from "../../fixtures/binjaMcp.js";
import { serveCli } from "./cliServeHarness.js";

// Port 1 on loopback refuses connections, so no engine is ever contacted.
const binjaEnvironment = {
  REA_BINJA_MCP_URL: "http://127.0.0.1:1/mcp",
  REA_ANALYSIS_PROVIDER: "binja",
};
const json = (text: string): unknown => JSON.parse(text);

it("reports an unreachable Binary Ninja endpoint with recovery guidance", async () => {
  const { target } = await materializeBinjaTarget();
  const result = await serveCli(
    ["decompile", target.path, "main", "--json"],
    binjaEnvironment,
  );
  expect(json(result.stdout)).toMatchObject({
    error: "Analysis failed",
    code: "execution_failure",
    message: expect.stringContaining("REA_BINJA_MCP_URL"),
    details: {
      provider_id: "binja",
      operation: "procedure_pseudo_code",
      diagnostics: { recovery: expect.stringContaining("REA_BINJA_MCP_URL") },
    },
  });
});

it("names the missing endpoint setting when binja is requested unconfigured", async () => {
  const { target } = await materializeBinjaTarget();
  const result = await serveCli(
    ["decompile", target.path, "main", "--provider", "binja", "--json"],
    {},
  );
  const failure = json(result.stdout);
  expect(failure).toMatchObject({
    code: "provider_unavailable",
    details: {
      selection_reason: "provider_unavailable",
      requested_provider_id: "binja",
    },
  });
  expect(result.stdout).toContain(
    "Set REA_BINJA_MCP_URL to the MCP endpoint of a running Binary Ninja",
  );
});

it("validates the endpoint setting in doctor without connecting", async () => {
  const configured = await serveCli(
    ["doctor", "--provider", "binja", "--json"],
    binjaEnvironment,
  );
  expect(json(configured.stdout)).toMatchObject({
    scope: { providers: ["binja"] },
    scope_checks: expect.arrayContaining([
      expect.objectContaining({
        name: "binja-endpoint",
        ok: true,
        detail: expect.stringContaining("no connection was made"),
      }),
    ]),
  });
  const missing = await serveCli(
    ["doctor", "--provider", "binja", "--json"],
    {},
  );
  expect(json(missing.stdout)).toMatchObject({
    scope_checks: expect.arrayContaining([
      expect.objectContaining({ name: "binja-endpoint", ok: false }),
    ]),
  });
  expect(missing.stdout).toContain("REA_BINJA_MCP_URL");
});

it("rejects a non-loopback endpoint as configuration, never as a connection", async () => {
  const { target } = await materializeBinjaTarget();
  const result = await serveCli(["decompile", target.path, "main", "--json"], {
    REA_BINJA_MCP_URL: "http://example.com/mcp",
    REA_ANALYSIS_PROVIDER: "binja",
  });
  expect(result.stdout).toContain("REA_BINJA_MCP_URL");
  expect(result.stdout).toContain("literal loopback host");
  expect(result.stdout).not.toContain("fetch failed");
});
