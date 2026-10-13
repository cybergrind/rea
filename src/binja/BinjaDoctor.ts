import type { DoctorProviderInspection } from "../application/Doctor.js";
import { binjaMcpUrlSchema } from "../config/binjaMcpEndpoint.js";

/** Check the endpoint setting without connecting to Binary Ninja. */
export const inspectBinjaEndpoint = (
  url: string | undefined,
): DoctorProviderInspection => {
  const parsed =
    url === undefined ? undefined : binjaMcpUrlSchema.safeParse(url);
  const valid = parsed?.success === true;
  return {
    id: "binja",
    configured: url !== undefined,
    available: valid,
    providerVersion: null,
    registrationEnvironment:
      valid && url !== undefined ? { REA_BINJA_MCP_URL: url } : {},
    checks: [
      {
        name: "endpoint",
        ok: valid,
        code: valid
          ? null
          : url === undefined
            ? "not_configured"
            : "invalid_configuration",
        detail: valid
          ? "Binary Ninja MCP endpoint setting is valid. Whether Binary Ninja is running, which view is active, and target binding are checked when analysis starts; no connection was made."
          : parsed !== undefined && !parsed.success
            ? (parsed.error.issues[0]?.message ??
              "REA_BINJA_MCP_URL is invalid.")
            : "Binary Ninja MCP endpoint is not configured.",
        remediation: valid
          ? null
          : "Set REA_BINJA_MCP_URL to the loopback MCP endpoint of a running Binary Ninja; see docs/binja-provider.md.",
        classification:
          url === undefined ? "missing_analysis_engine" : "config_drift",
      },
    ],
  };
};
