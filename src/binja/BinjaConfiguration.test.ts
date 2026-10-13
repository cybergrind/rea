import { expect, it } from "vitest";
import { parseConfig } from "../config/parseConfig.js";
import { readBinjaConfiguration } from "./BinjaConfiguration.js";
import { inspectBinjaEndpoint } from "./BinjaDoctor.js";

it("selects the endpoint only from an explicit URL", () => {
  const unset = parseConfig({});
  if (!unset.ok) throw unset.error;
  const missing = readBinjaConfiguration(unset.value);
  if (missing.ok) throw new Error("An unset endpoint must not configure binja");
  expect(missing.error._tag).toBe("ConfigurationError");
  expect(missing.error.settings).toMatchObject([
    { setting: "REA_BINJA_MCP_URL" },
  ]);
  const set = parseConfig({
    REA_BINJA_MCP_URL: "http://127.0.0.1:24642/mcp",
    REA_BINJA_MCP_TIMEOUT_MS: "1500",
  });
  if (!set.ok) throw set.error;
  const selected = readBinjaConfiguration(set.value);
  if (!selected.ok) throw selected.error;
  expect(selected.value).toEqual({
    url: "http://127.0.0.1:24642/mcp",
    timeoutMs: 1500,
  });
});

it("diagnoses the endpoint setting without connecting", () => {
  expect(inspectBinjaEndpoint(undefined)).toMatchObject({
    id: "binja",
    configured: false,
    available: false,
    registrationEnvironment: {},
    checks: [{ ok: false, code: "not_configured" }],
  });
  expect(inspectBinjaEndpoint("http://example.com/mcp")).toMatchObject({
    configured: true,
    available: false,
    registrationEnvironment: {},
    checks: [{ ok: false, code: "invalid_configuration" }],
  });
  // Port 1 is closed; a valid result shows that no connection was attempted.
  expect(inspectBinjaEndpoint("http://127.0.0.1:1/mcp")).toMatchObject({
    configured: true,
    available: true,
    providerVersion: null,
    registrationEnvironment: { REA_BINJA_MCP_URL: "http://127.0.0.1:1/mcp" },
    checks: [{ name: "endpoint", ok: true, code: null }],
  });
});
