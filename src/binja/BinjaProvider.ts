import type {
  AnalysisClient,
  AnalysisProfileResolutionOptions,
  AnalysisProviderCandidate,
  ProviderAvailability,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import type { AppConfig } from "../config/types.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { err, ok } from "../domain/result.js";
import {
  readBinjaConfiguration,
  type BinjaConfiguration,
} from "./BinjaConfiguration.js";
import {
  createBinjaMcpConnection,
  type BinjaMcpConnection,
} from "./BinjaMcpConnection.js";
import {
  BINJA_CAPABILITIES,
  BINJA_PROVIDER_IDENTITY,
  BINJA_READ_ONLY_TOOLS,
} from "./BinjaProviderCapabilities.js";
import { BinjaSessionClient } from "./BinjaSessionClient.js";

/** Bring-your-own Binary Ninja candidate; discovery never connects to the GUI. */
export class BinjaProvider implements AnalysisProviderCandidate {
  constructor(
    private readonly config: AppConfig,
    private readonly connectionFactory: (
      config: BinjaConfiguration,
    ) => BinjaMcpConnection = (config) =>
      createBinjaMcpConnection(config, BINJA_READ_ONLY_TOOLS),
  ) {}

  identity() {
    return BINJA_PROVIDER_IDENTITY;
  }
  capabilities() {
    return BINJA_CAPABILITIES;
  }
  inspectAvailability(): ProviderAvailability {
    const config = readBinjaConfiguration(this.config);
    return config.ok
      ? {
          status: "available",
          code: null,
          reason: null,
          diagnostics: {
            configured: true,
            mode: "attached",
            transport: "http",
            live_connection_probed: false,
          },
        }
      : {
          status: "unavailable",
          code: "not_configured",
          reason: config.error.message,
          diagnostics: { configured: false, live_connection_probed: false },
        };
  }
  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const diagnostics = {
      target_kind: target.kind,
      target_format: target.format,
    };
    if (target.kind === "executable" && target.architecture === "mips")
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "REA's Binary Ninja adapter has no verified MIPS lane. Select a supported Ghidra profile instead.",
        diagnostics,
      };
    return target.kind === "executable"
      ? { status: "supported", code: null, reason: null, diagnostics }
      : {
          status: "unsupported",
          code: "target_kind_unsupported",
          reason:
            "The Binary Ninja adapter admits executable inputs, not analysis databases. Select the original input binary; its saved .bndb may be the item open in Binary Ninja.",
          diagnostics,
        };
  }
  async resolveAnalysisProfile(
    _target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ) {
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError("binja:profile"));
    const config = readBinjaConfiguration(this.config);
    if (!config.ok) return config;
    return ok({
      profile: createAnalysisProfile(BINJA_PROVIDER_IDENTITY, {
        version_scope: "rea-binja-adapter",
        engine_version: null,
        mode: "attached",
        endpoint: config.value.url,
        database_revision: null,
        cache_policy: "live",
      }),
    });
  }
  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
  ): AnalysisClient {
    const config = readBinjaConfiguration(this.config);
    if (!config.ok)
      return {
        execute: async () => err(config.error),
        close: async () => ok(null),
      };
    return new BinjaSessionClient(
      target,
      this.connectionFactory(config.value),
      profile,
    );
  }
}
