import type { z } from "zod";
import {
  AnalysisCancelledError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { EvidenceLocation } from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { BinjaMcpConnection } from "./BinjaMcpConnection.js";
import {
  binjaFunctionMetaSchema,
  binjaPageSchema,
  parseBinjaText,
  type BinjaTextReply,
} from "./BinjaProtocolValues.js";

/** Every listing tool caps one page at this many items or lines. */
export const BINJA_PAGE_LIMIT = 1000;

/** One upstream request retained beside the normalized result. */
export interface BinjaRawObservation {
  readonly tool: string;
  readonly arguments: Readonly<Record<string, JsonValue>>;
  /** The complete reply, or only its front matter for an inventory page. */
  readonly result: JsonValue;
}

type Arguments = Readonly<Record<string, JsonValue>>;

/**
 * Serial, cancellable reads of one operation.
 *
 * Inventory walks retain page front matter instead of page bodies: the rows
 * already form the normalized result, and a second copy of a million-row
 * listing would only double the allocation.
 */
export class BinjaToolReader {
  readonly raw: BinjaRawObservation[] = [];
  readonly locations: EvidenceLocation[] = [];
  readonly limitations: string[] = [];

  constructor(
    private readonly connection: BinjaMcpConnection,
    private readonly signal?: AbortSignal,
  ) {}

  /** Record a result limitation once. */
  limit(text: string): void {
    if (!this.limitations.includes(text)) this.limitations.push(text);
  }

  #throwIfCancelled(tool: string): void {
    if (this.signal?.aborted === true) throw new AnalysisCancelledError(tool);
  }

  async #request(tool: string, args: Arguments): Promise<JsonValue> {
    this.#throwIfCancelled(tool);
    const result = await this.connection.call(tool, args);
    this.#throwIfCancelled(tool);
    return result;
  }

  /** Call a tool that answers with one JSON document. */
  async structured<Schema extends z.ZodType>(
    tool: string,
    args: Arguments,
    schema: Schema,
  ): Promise<z.infer<Schema>> {
    const result = await this.#request(tool, args);
    this.raw.push({ tool, arguments: args, result });
    if (typeof result === "string")
      throw new AnalysisProtocolError(
        `Binary Ninja MCP tool ${tool} returned text where a structured result was expected.`,
      );
    return schema.parse(result);
  }

  /** Call a tool that answers with front matter and a markdown body. */
  async text(
    tool: string,
    args: Arguments,
    retain: "reply" | "front-matter" = "reply",
  ): Promise<BinjaTextReply> {
    const result = await this.#request(tool, args);
    if (typeof result !== "string")
      throw new AnalysisProtocolError(
        `Binary Ninja MCP tool ${tool} returned a structured result where text was expected.`,
      );
    const reply = parseBinjaText(result);
    this.raw.push({
      tool,
      arguments: args,
      result: retain === "reply" ? result : { front_matter: reply.meta },
    });
    return reply;
  }

  /** Follow reported offsets until the listing finishes; a page must advance. */
  async *pages(
    tool: string,
    args: Arguments,
    retain: "reply" | "front-matter" = "reply",
  ): AsyncGenerator<{
    reply: BinjaTextReply;
    page: z.infer<typeof binjaPageSchema>;
  }> {
    let offset: number | null = 0;
    while (offset !== null) {
      const reply = await this.text(
        tool,
        { ...args, offset, limit: BINJA_PAGE_LIMIT },
        retain,
      );
      const page = binjaPageSchema.parse(reply.meta);
      yield { reply, page };
      if (page.nextOffset !== null && page.nextOffset <= offset)
        throw new AnalysisProtocolError(
          `Binary Ninja MCP ${tool} pagination did not advance.`,
        );
      offset = page.nextOffset;
    }
  }

  /** Read every row of a paged table through one row schema. */
  async rows<Schema extends z.ZodType>(
    tool: string,
    args: Arguments,
    schema: Schema,
    options: {
      readonly retain?: "reply" | "front-matter";
      /** Require the walk to return exactly the reported total. */
      readonly exhaustive?: boolean;
    } = {},
  ): Promise<z.infer<Schema>[]> {
    const rows: z.infer<Schema>[] = [];
    const totals = new Set<number>();
    for await (const { reply, page } of this.pages(
      tool,
      args,
      options.retain,
    )) {
      totals.add(page.total);
      for (const row of reply.tables[0]?.rows ?? [])
        rows.push(schema.parse(row));
    }
    if (
      options.exhaustive === true &&
      (totals.size !== 1 || !totals.has(rows.length))
    )
      throw new AnalysisProtocolError(
        `Binary Ninja MCP ${tool} listed ${String(rows.length)} items against reported totals of ${[...totals].join(", ")}; the inventory changed during the walk or a page was cut.`,
      );
    return rows;
  }

  /** Concatenate the paged code block one function-scoped tool renders. */
  async block(tool: string, address: string): Promise<string | null> {
    const parts: string[] = [];
    for await (const { reply } of this.pages(tool, { function: address })) {
      const described = binjaFunctionMetaSchema.parse(reply.meta);
      if (described.function !== address)
        throw new AnalysisProtocolError(
          `Binary Ninja MCP ${tool} describes a different function than the resolved entry.`,
        );
      if (reply.block !== null) parts.push(reply.block);
    }
    return parts.length === 0 ? null : parts.join("\n");
  }
}
