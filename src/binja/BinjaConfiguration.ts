import type { AppConfig } from "../config/types.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";

/** One attached Binary Ninja MCP endpoint and its per-request deadline. */
export interface BinjaConfiguration {
  readonly url: string;
  readonly timeoutMs: number;
}

/** A REA_BINJA_MCP_URL rejection that names the setting it concerns. */
export const binjaConfigurationError = (
  constraint: string,
): ConfigurationError =>
  new ConfigurationError(constraint, {
    settings: [{ setting: "REA_BINJA_MCP_URL", constraint }],
  });

/**
 * Select the endpoint without connecting. The provider is configured only by
 * an explicit URL: a default endpoint would make every host with a second
 * provider ambiguous under automatic selection.
 */
export const readBinjaConfiguration = (
  config: Pick<AppConfig, "binjaMcpUrl" | "binjaMcpTimeoutMs">,
): Result<BinjaConfiguration, ConfigurationError> =>
  config.binjaMcpUrl === undefined
    ? err(
        binjaConfigurationError(
          "Set REA_BINJA_MCP_URL to the MCP endpoint of a running Binary Ninja; see docs/binja-provider.md.",
        ),
      )
    : ok({ url: config.binjaMcpUrl, timeoutMs: config.binjaMcpTimeoutMs });
