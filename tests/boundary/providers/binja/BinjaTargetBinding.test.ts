import { appendFile, utimes, writeFile } from "node:fs/promises";
import { join, parse } from "node:path";
import { describe, expect, it } from "vitest";
import { BinjaTargetBinding } from "../../../../src/binja/BinjaTargetBinding.js";
import {
  BinjaProducerFixture,
  materializeBinjaTarget,
} from "../../../fixtures/binjaMcp.js";

const fixture = async (name?: string) => {
  const { root, target } = await materializeBinjaTarget(name);
  const producer = new BinjaProducerFixture(target);
  return {
    root,
    target,
    producer,
    binding: new BinjaTargetBinding(producer, target),
  };
};
/** A binding refusal is typed so its reason and recovery reach the caller. */
const refusal = (reason: string) => ({
  _tag: "ProviderAdapterError",
  providerId: "binja",
  operation: "target_binding",
  userMessage: expect.stringContaining(reason),
  diagnostics: {
    reason: expect.stringContaining(reason),
    recovery: expect.any(String),
  },
});
const toolsCalled = (producer: BinjaProducerFixture) =>
  producer.calls.map(({ name }) => name);

describe("binding a target to the active Binary Ninja view", () => {
  it("accepts the saved database beside the target and reports what it observed", async () => {
    const { binding, producer, target } = await fixture();
    expect(await binding.observe()).toEqual({
      binary_view: "view_1",
      open_item: "item_1",
      view_type: "ELF",
      image_base: "0x1000",
      end: "0x5000",
      architecture: "x86_64",
      platform: "linux-x86_64",
      analysis_state: "IdleState",
      open_item_path: `${target.path}.bndb`,
      open_item_kind: "database",
      path_relation: "sibling-database",
      raw_view_bytes: 64,
      header_bytes_match: true,
      target_sha256: target.sha256,
    });
    expect(binding.limitations).toEqual([]);
    expect(toolsCalled(producer)).toEqual([
      "bn_binary_view_list",
      "bn_open_item_list",
      "bn_segment_list",
      "bn_memory_read",
      "bn_analysis_status",
    ]);
    // Later observations re-read only the active view and analysis state.
    await binding.observe();
    expect(toolsCalled(producer).slice(5)).toEqual([
      "bn_binary_view_list",
      "bn_analysis_status",
    ]);
  });

  it("accepts the target path itself and the stem-named database", async () => {
    const direct = await fixture();
    direct.producer.itemPath = direct.target.path;
    expect(await direct.binding.observe()).toMatchObject({
      path_relation: "target",
    });
    const stem = await fixture("target.elf");
    const { dir, name } = parse(stem.target.path);
    stem.producer.itemPath = join(dir, `${name}.bndb`);
    expect(await stem.binding.observe()).toMatchObject({
      path_relation: "sibling-database",
    });
    expect(stem.binding.limitations).toEqual([]);
  });

  it("accepts an unrelated path only on matching content and records that", async () => {
    const matching = await fixture();
    matching.producer.itemPath = "/databases/renamed.bndb";
    expect(await matching.binding.observe()).toMatchObject({
      path_relation: "unrelated",
      raw_view_bytes: 64,
      header_bytes_match: true,
    });
    expect(matching.binding.limitations).toEqual([
      expect.stringContaining("path unrelated to the target"),
    ]);
    const unverifiable = await fixture();
    unverifiable.producer.itemPath = "/databases/renamed.bndb";
    unverifiable.producer.rawBytes = null;
    unverifiable.producer.firstSegmentOffset = 0x400;
    await expect(unverifiable.binding.observe()).rejects.toMatchObject(
      refusal("does not hold the selected target"),
    );
  });

  it("rejects a raw size or header that differs from the target file", async () => {
    const size = await fixture();
    size.producer.rawBytes = 65;
    await expect(size.binding.observe()).rejects.toMatchObject(
      refusal("its raw size or header bytes differ"),
    );
    const header = await fixture();
    header.producer.header.writeUInt8(
      header.producer.header.readUInt8(5) ^ 0xff,
      5,
    );
    await expect(header.binding.observe()).rejects.toMatchObject(
      refusal("its raw size or header bytes differ"),
    );
    // A failed binding is not remembered as bound.
    header.producer.header.writeUInt8(
      header.producer.header.readUInt8(5) ^ 0xff,
      5,
    );
    expect(await header.binding.observe()).toMatchObject({
      header_bytes_match: true,
    });
  });

  it("records fewer content checks when a raw view or offset-zero bytes are missing", async () => {
    const noRaw = await fixture();
    noRaw.producer.rawBytes = null;
    expect(await noRaw.binding.observe()).toMatchObject({
      raw_view_bytes: null,
      header_bytes_match: true,
    });
    const noHeader = await fixture();
    noHeader.producer.firstSegmentOffset = 0x400;
    expect(await noHeader.binding.observe()).toMatchObject({
      raw_view_bytes: 64,
      header_bytes_match: null,
    });
    expect(toolsCalled(noHeader.producer)).not.toContain("bn_memory_read");
    for (const { binding } of [noRaw, noHeader])
      expect(binding.limitations).toEqual([
        expect.stringContaining("fewer content checks"),
      ]);
  });
});

describe("rejecting a view that is not the bound, idle target", () => {
  it.each([
    [[], "0 active views"],
    [["view_1", "view_2"], "2 active views"],
  ])("rejects %j as the set of active views", async (active, reason) => {
    const { binding, producer } = await fixture();
    producer.activeViews = active;
    await expect(binding.observe()).rejects.toMatchObject(refusal(reason));
    expect(producer.calls.map(({ name }) => name)).toEqual([
      "bn_binary_view_list",
    ]);
  });

  it("rejects an active view or image base that changes between observations", async () => {
    const view = await fixture();
    await view.binding.observe();
    view.producer.activeViews = ["view_2"];
    await expect(view.binding.observe()).rejects.toMatchObject(
      refusal("active Binary Ninja view or its image base changed"),
    );
    view.producer.activeViews = ["view_1"];
    expect(await view.binding.observe()).toMatchObject({
      binary_view: "view_1",
    });
    const base = await fixture();
    await base.binding.observe();
    base.producer.imageBase = "0x2000";
    await expect(base.binding.observe()).rejects.toMatchObject(
      refusal("active Binary Ninja view or its image base changed"),
    );
  });

  it("rejects a target whose bytes differ from the admitted digest", async () => {
    const { binding, target } = await fixture();
    await writeFile(target.path, Buffer.alloc(64, 1));
    await expect(binding.observe()).rejects.toMatchObject({
      _tag: "AnalysisArtifactChangedError",
      path: target.path,
      reason: expect.stringContaining("no longer matches the admitted target"),
    });
  });

  it("rejects a target whose size or modification time changes mid-session", async () => {
    const grown = await fixture();
    await grown.binding.observe();
    await appendFile(grown.target.path, "x");
    await expect(grown.binding.observe()).rejects.toMatchObject({
      _tag: "AnalysisArtifactChangedError",
      path: grown.target.path,
    });
    const touched = await fixture();
    await touched.binding.observe();
    const later = new Date(Date.now() + 60_000);
    await utimes(touched.target.path, later, later);
    await expect(touched.binding.observe()).rejects.toMatchObject({
      _tag: "AnalysisArtifactChangedError",
      reason: expect.stringContaining("size or modification time changed"),
    });
  });

  it("refuses partial analysis at binding and afterwards", async () => {
    const { binding, producer } = await fixture();
    producer.analysisState = "AnalyzeState";
    await expect(binding.observe()).rejects.toMatchObject(
      refusal("analysis is AnalyzeState, not IdleState"),
    );
    producer.analysisState = "IdleState";
    await binding.observe();
    producer.analysisState = "ExtendedAnalyzeState";
    await expect(binding.observe()).rejects.toMatchObject(
      refusal("ExtendedAnalyzeState"),
    );
  });
});
