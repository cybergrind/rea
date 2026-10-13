import { describe, expect, it } from "vitest";
import { createAnalysisExecution } from "../../src/application/AnalysisProvider.js";
import { BinjaProvider } from "../../src/binja/BinjaProvider.js";
import { BINJA_PROVIDER_IDENTITY } from "../../src/binja/BinjaProviderCapabilities.js";
import { parseConfig } from "../../src/config/parseConfig.js";
import {
  createAnalysisSnapshotEntry,
  snapshotBinding,
  snapshotTarget,
} from "../../src/domain/analysisSnapshot.js";
import { createEvidence } from "../../src/domain/evidence.js";
import { createEvidenceBundle } from "../../src/domain/evidenceBundle.js";
import { createTestBinarySession } from "../fixtures/binarySession.js";
import {
  BinjaProducerFixture,
  materializeBinjaTarget,
} from "../fixtures/binjaMcp.js";

const compose = async () => {
  const { target } = await materializeBinjaTarget();
  const config = parseConfig({
    REA_BINJA_MCP_URL: "http://127.0.0.1:24642/mcp",
  });
  if (!config.ok) throw config.error;
  const producer = new BinjaProducerFixture(target);
  const session = createTestBinarySession(
    new BinjaProvider(config.value, () => producer),
  );
  return { target, producer, session };
};

describe("Binary Ninja provider composition", () => {
  it("opens a target without connecting and binds on the first analysis", async () => {
    const { target, producer, session } = await compose();
    const opened = await session.open(target.path);
    if (!opened.ok) throw opened.error;
    expect(producer.connects).toBe(0);
    expect(session.analysisProfile()).toMatchObject({
      provider: BINJA_PROVIDER_IDENTITY,
      parameters: { version_scope: "rea-binja-adapter", cache_policy: "live" },
    });
    const analyzed = await session.execute("procedure_address", {
      procedure: "main",
    });
    if (!analyzed.ok) throw analyzed.error;
    expect(analyzed.value.provider).toEqual(BINJA_PROVIDER_IDENTITY);
    expect(producer.connects).toBe(1);
    const closed = await session.close();
    if (!closed.ok) throw closed.error;
    expect(producer.closes).toBe(1);
  });

  it("re-observes the externally mutable database instead of replaying a snapshot", async () => {
    const { target, producer, session } = await compose();
    const opened = await session.open(target.path);
    if (!opened.ok) throw opened.error;
    const query = { procedure: "main", document: target.path };
    const first = await session.execute("procedure_pseudo_code", query);
    if (!first.ok) throw first.error;
    expect(first.value.result).toContain("return 42;");
    const snapshot = session.exportAnalysisSnapshot();
    if (!snapshot.ok) throw snapshot.error;
    expect(snapshot.value.entries).toEqual([]);
    const profile = session.analysisProfile();
    if (profile === undefined) throw new Error("Missing profile");
    const cached = createAnalysisExecution(
      "stale output",
      BINJA_PROVIDER_IDENTITY,
      {
        analysisProfile: profile,
        subject: {
          path: target.path,
          sha256: target.sha256,
          format: target.format,
          ...(target.architecture === undefined
            ? {}
            : { architecture: target.architecture }),
        },
      },
    );
    snapshot.value.entries.push(
      createAnalysisSnapshotEntry({
        target: snapshotTarget(target),
        binding: snapshotBinding(profile),
        operation: "procedure_pseudo_code",
        parameters: query,
        execution: cached,
      }),
    );
    snapshot.value.evidence_bundle = createEvidenceBundle([
      ...snapshot.value.evidence_bundle.records,
      createEvidence(target, BINJA_PROVIDER_IDENTITY, {
        operation: "procedure_pseudo_code",
        parameters: query,
        result: cached.result,
        rawResult: cached.rawResult,
        analysisProfile: profile,
      }),
    ]);
    const imported = session.importAnalysisSnapshot(snapshot.value);
    if (!imported.ok) throw imported.error;
    expect(session.allowsSnapshotReplay("procedure_pseudo_code")).toBe(false);
    const second = await session.execute("procedure_pseudo_code", query);
    if (!second.ok) throw second.error;
    expect(second.value.result).toContain("return 42;");
    expect(
      producer.calls.filter(({ name }) => name === "bn_function_decompile"),
    ).toHaveLength(2);
    await session.close();
  });

  it("reports refused operations as unavailable without reaching Binary Ninja", async () => {
    const { target, producer, session } = await compose();
    const opened = await session.open(target.path);
    if (!opened.ok) throw opened.error;
    const refused = await session.execute("set_comment", {
      address: "0x1000",
      comment: "analyst note",
    });
    if (refused.ok) throw new Error("A read-only provider must not write");
    expect(refused.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(producer.calls).toEqual([]);
    await session.close();
  });
});
