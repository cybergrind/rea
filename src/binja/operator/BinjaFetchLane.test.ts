import { describe, expect, it } from "vitest";
import {
  BinjaFetchError,
  fetchCommand,
  parseFetchQueue,
} from "./BinjaFetchLane.js";

describe("fetch lane queue text", () => {
  it("normalizes addresses, ignores comments, and orders plain requests first", () => {
    expect(
      parseFetchQueue(
        [
          "# header comment",
          "",
          "full 0x18D7F7950  # dossier wanted",
          "180001880 why: caller of the logger",
          "  0X1904AAC90",
          "full 1904aac90",
          "0x180001880",
        ].join("\r\n"),
      ),
    ).toEqual([
      { address: "0x180001880", full: false },
      { address: "0x18d7f7950", full: true },
      { address: "0x1904aac90", full: true },
    ]);
    expect(parseFetchQueue("")).toEqual([]);
  });

  it("keeps addresses above 2^53 exact", () => {
    expect(parseFetchQueue("0xFFFFFFFFFFFFFFFF")).toEqual([
      { address: "0xffffffffffffffff", full: false },
    ]);
  });

  it.each([
    ["main", 'line 1: "main" is not a hex address'],
    ["0x1000\nfull", 'line 2: "" is not a hex address'],
    ["0x1000\n\nfull sub_1000", 'line 3: "sub_1000" is not a hex address'],
  ])("rejects %j with its line number", (text, reason) => {
    expect(() => parseFetchQueue(text)).toThrow(BinjaFetchError);
    expect(() => parseFetchQueue(text)).toThrow(reason);
  });

  it("maps a request to the public REA command that answers it", () => {
    expect(fetchCommand({ address: "0x1000", full: false })).toBe("decompile");
    expect(fetchCommand({ address: "0x1000", full: true })).toBe("function");
  });
});
