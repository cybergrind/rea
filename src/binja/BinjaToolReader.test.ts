import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  binjaBlock,
  binjaPage,
  binjaRequest,
  scriptedBinjaConnection,
} from "../../tests/fixtures/binjaMcp.js";
import {
  AnalysisCancelledError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { BINJA_PAGE_LIMIT, BinjaToolReader } from "./BinjaToolReader.js";

const headers = ["segment", "start", "end"];
const segments = Array.from({ length: 2300 }, (_, index) => [
  `0x${(index * 16).toString(16)}`,
  `0x${(index * 16).toString(16)}`,
  `0x${(index * 16 + 16).toString(16)}`,
]);
const rowSchema = z.looseObject({ segment: z.string() });
const pageArgs = (offset: number) => ({ offset, limit: BINJA_PAGE_LIMIT });
const script = (entries: readonly (readonly [string, JsonValue | Error])[]) =>
  scriptedBinjaConnection(new Map(entries));
const pagesOf = (tool: string, rows: readonly (readonly string[])[]) =>
  [0, 1000, 2000].map(
    (offset) =>
      [
        binjaRequest(tool, pageArgs(offset)),
        binjaPage(tool, pageArgs(offset), { headers, rows }),
      ] as const,
  );
const lead = { function: "0x1000", arch: "x86_64", name: "main" };

describe("paged Binary Ninja reads", () => {
  it("walks every page in order and retains whole replies by default", async () => {
    const connection = script(pagesOf("bn_segment_list", segments));
    const reader = new BinjaToolReader(connection);
    const rows = await reader.rows("bn_segment_list", {}, rowSchema, {
      exhaustive: true,
    });
    expect(rows).toHaveLength(2300);
    expect(rows.at(-1)?.segment).toBe("0x8fb0");
    expect(connection.calls).toHaveLength(3);
    expect(reader.raw).toHaveLength(3);
    expect(String(reader.raw[2]?.result)).toContain("| 0x8fb0 |");
  });

  it("retains only front matter when asked, never a second copy of the rows", async () => {
    const reader = new BinjaToolReader(
      script(pagesOf("bn_segment_list", segments)),
    );
    await reader.rows("bn_segment_list", {}, rowSchema, {
      retain: "front-matter",
    });
    expect(reader.raw[0]?.result).toEqual({
      front_matter: {
        tool: "bn_segment_list",
        offset: 0,
        limit: 1000,
        count: 1000,
        total: 2300,
        nextOffset: 1000,
        truncated: true,
      },
    });
    expect(JSON.stringify(reader.raw)).not.toContain("0x8fb0");
  });

  it("fails when pagination does not advance", async () => {
    const stuck = binjaPage("bn_segment_list", pageArgs(0), {
      headers,
      rows: segments,
    }).replace("nextOffset: 1000", "nextOffset: 0");
    const reader = new BinjaToolReader(
      script([[binjaRequest("bn_segment_list", pageArgs(0)), stuck]]),
    );
    await expect(reader.rows("bn_segment_list", {}, rowSchema)).rejects.toThrow(
      "pagination did not advance",
    );
  });

  it("fails an exhaustive walk whose rows differ from the reported total", async () => {
    const pages = pagesOf("bn_segment_list", segments);
    const shrunk = pagesOf("bn_segment_list", segments.slice(0, 2100));
    const [first, second] = pages;
    const last = shrunk[2];
    if (first === undefined || second === undefined || last === undefined)
      throw new Error("Expected three pages");
    const reader = new BinjaToolReader(script([first, second, last]));
    await expect(
      reader.rows("bn_segment_list", {}, rowSchema, { exhaustive: true }),
    ).rejects.toThrow(
      "listed 2100 items against reported totals of 2300, 2100",
    );
    const tolerant = new BinjaToolReader(script([first, second, last]));
    expect(await tolerant.rows("bn_segment_list", {}, rowSchema)).toHaveLength(
      2100,
    );
  });

  it("concatenates code pages and rejects a page for another function", async () => {
    const lines = Array.from(
      { length: 1200 },
      (_, index) => `line ${String(index)}`,
    );
    const tool = "bn_function_disassembly";
    const page = (offset: number, described = lead) =>
      [
        binjaRequest(tool, { function: "0x1000", ...pageArgs(offset) }),
        binjaBlock(tool, pageArgs(offset), {
          lead: described,
          fence: "asm",
          lines,
        }),
      ] as const;
    const reader = new BinjaToolReader(script([page(0), page(1000)]));
    const text = await reader.block(tool, "0x1000");
    expect(text?.split("\n")).toHaveLength(1200);
    expect(text?.endsWith("line 1199")).toBe(true);
    const other = new BinjaToolReader(
      script([page(0), page(1000, { ...lead, function: "0x2000" })]),
    );
    await expect(other.block(tool, "0x1000")).rejects.toThrow(
      "describes a different function",
    );
  });

  it("rejects the wrong reply kind in both directions", async () => {
    const status = { analysis: { state: "IdleState" } };
    const text = binjaPage("bn_segment_list", {}, { headers, rows: [] });
    const reader = new BinjaToolReader(
      script([
        [binjaRequest("bn_segment_list", {}), status],
        [binjaRequest("bn_analysis_status", {}), text],
      ]),
    );
    await expect(reader.text("bn_segment_list", {})).rejects.toThrow(
      AnalysisProtocolError,
    );
    await expect(
      reader.structured("bn_analysis_status", {}, z.looseObject({})),
    ).rejects.toThrow("returned text where a structured result was expected");
  });

  it("observes cancellation before a call and after it returns", async () => {
    const request = binjaRequest("bn_analysis_status", {});
    const before = new AbortController();
    before.abort();
    const untouched = script([[request, {}]]);
    await expect(
      new BinjaToolReader(untouched, before.signal).structured(
        "bn_analysis_status",
        {},
        z.looseObject({}),
      ),
    ).rejects.toThrow(AnalysisCancelledError);
    expect(untouched.calls).toEqual([]);

    const during = new AbortController();
    const inner = script([[request, {}]]);
    const reader = new BinjaToolReader(
      {
        ...inner,
        async call(name, args) {
          const reply = await inner.call(name, args);
          during.abort();
          return reply;
        },
      },
      during.signal,
    );
    await expect(
      reader.structured("bn_analysis_status", {}, z.looseObject({})),
    ).rejects.toThrow(AnalysisCancelledError);
    expect(reader.raw).toEqual([]);
  });

  it("records a limitation once", () => {
    const reader = new BinjaToolReader(script([]));
    reader.limit("first");
    reader.limit("second");
    reader.limit("first");
    expect(reader.limitations).toEqual(["first", "second"]);
  });
});
