import { describe, expect, it } from "vitest";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import {
  BinjaToolError,
  createBinjaMcpConnection,
  decodeBinjaToolResult,
} from "./BinjaMcpConnection.js";
import { BINJA_READ_ONLY_TOOLS } from "./BinjaProviderCapabilities.js";

const caught = (run: () => unknown): unknown => {
  try {
    run();
  } catch (cause: unknown) {
    return cause;
  }
  throw new Error("Expected the decoder to throw");
};

describe("decodeBinjaToolResult", () => {
  it("preserves Binary Ninja's error code and reason", () => {
    const refusal = {
      errorCode: "function_not_found",
      errorMessage: "No matching function was found",
    };
    const error = caught(() =>
      decodeBinjaToolResult("bn_function_info", {
        isError: true,
        structuredContent: refusal,
        content: [{ type: "text", text: JSON.stringify(refusal) }],
      }),
    );
    expect(error).toBeInstanceOf(BinjaToolError);
    expect(error).toBeInstanceOf(AnalysisProtocolError);
    expect(error).toMatchObject({
      tool: "bn_function_info",
      code: "function_not_found",
      reason: "No matching function was found",
    });
  });

  it("reports an unstructured failure as unreported with the engine text", () => {
    expect(
      caught(() =>
        decodeBinjaToolResult("bn_memory_read", {
          isError: true,
          content: [{ type: "text", text: "view is gone" }],
        }),
      ),
    ).toMatchObject({ code: "unreported", reason: "view is gone" });
    expect(
      caught(() =>
        decodeBinjaToolResult("bn_memory_read", { isError: true, content: [] }),
      ),
    ).toMatchObject({ code: "unreported", reason: "unexplained failure" });
  });

  it("returns a structured document and ignores its text rendering", () => {
    const document = { comment: "0x1000", text: "", warnings: [] };
    expect(
      decodeBinjaToolResult("bn_comment_get", {
        structuredContent: document,
        content: [{ type: "text", text: JSON.stringify(document) }],
      }),
    ).toEqual(document);
  });

  it("returns a single text block verbatim, never parsed as JSON", () => {
    expect(
      decodeBinjaToolResult("bn_segment_list", {
        content: [
          { type: "text", text: '---\ntool: "bn_segment_list"\n---\n' },
        ],
      }),
    ).toBe('---\ntool: "bn_segment_list"\n---\n');
    expect(
      decodeBinjaToolResult("bn_segment_list", {
        content: [{ type: "text", text: "{}" }],
      }),
    ).toBe("{}");
  });

  it("rejects contentless and multi-block results instead of inventing an observation", () => {
    for (const content of [
      [],
      [{ type: "image", data: "AA==" }],
      [
        { type: "text", text: "first" },
        { type: "text", text: "second" },
      ],
    ])
      expect(() =>
        decodeBinjaToolResult("bn_segment_list", { content }),
      ).toThrow(AnalysisProtocolError);
  });
});

it.each([
  "bn_open_item_save",
  "bn_open_item_open",
  "bn_open_item_close",
  "bn_binary_view_set_active",
  "bn_symbol_rename",
  "bn_comment_set",
  "bn_analysis_update",
])("refuses %s before anything reaches the network", async (tool) => {
  expect(BINJA_READ_ONLY_TOOLS.has(tool)).toBe(false);
  // Port 1 is never connected to: the refusal precedes any transport use.
  const connection = createBinjaMcpConnection(
    { url: "http://127.0.0.1:1/mcp", timeoutMs: 50 },
    BINJA_READ_ONLY_TOOLS,
  );
  await expect(connection.call(tool, {})).rejects.toThrow(
    `${tool} is outside this connection's authority and was not called`,
  );
});

it("admits only reading tools into the provider's authority", () => {
  expect(
    [...BINJA_READ_ONLY_TOOLS].filter((tool) =>
      /_(?:set|save|open|close|rename|define|undefine|create|modify|delete|update|abort|parse|set_active|set_type|update_and_wait)$/u.test(
        tool,
      ),
    ),
  ).toEqual([]);
});
