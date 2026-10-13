import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";
import { BINJA_OPERATIONS } from "../../../src/binja/BinjaProviderCapabilities.js";
import { BinjaSessionClient } from "../../../src/binja/BinjaSessionClient.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import type { JsonValue } from "../../../src/domain/jsonValue.js";
import { ToolResultDelivery } from "../../../src/server/toolResult.js";
import {
  BinjaProducerFixture,
  materializeBinjaTarget,
} from "../../fixtures/binjaMcp.js";

const delivery = new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE);

const parametersFor = (
  operation: string,
): Readonly<Record<string, JsonValue>> => {
  if (operation.startsWith("search_")) return { pattern: "a.b" };
  if (operation.startsWith("list_")) return {};
  if (operation === "read_bytes") return { address: "0x3000", length: 5 };
  if (
    [
      "xrefs",
      "comment",
      "address_name",
      "address_to_file_offset",
      "resolve_containing_procedure",
    ].includes(operation)
  )
    return { address: "0x1000" };
  return { procedure: "main" };
};

describe("Binary Ninja caller-visible contracts", () => {
  it.each(BINJA_OPERATIONS)(
    "serializes %s against its named advertised output contract",
    async (operation) => {
      const { target } = await materializeBinjaTarget();
      const client = new BinjaSessionClient(
        target,
        new BinjaProducerFixture(target),
      );
      try {
        const parameters = parametersFor(operation);
        const execution = await client.execute(operation, parameters);
        if (!execution.ok) throw execution.error;
        const evidence = createEvidence(target, execution.value.provider, {
          operation,
          parameters,
          result: execution.value.result,
          rawResult: execution.value.rawResult,
          locations: execution.value.locations,
          limitations: execution.value.limitations,
        });
        expect(evidence.provider.id).toBe("binja");
        const contract = toolContract(operation);
        const serialized = delivery.toEvidenceToolResult(
          evidence,
          contract,
          undefined,
        );
        const parsed = contract.outputSchema.safeParse(
          serialized.structuredContent,
        );
        if (!parsed.success) throw parsed.error;
        expect(serialized.content[0]).toEqual({
          type: "text",
          text: JSON.stringify(serialized.structuredContent),
        });
      } finally {
        await client.close();
      }
    },
  );
});
