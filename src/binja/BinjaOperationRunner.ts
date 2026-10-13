import { z } from "zod";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  BinjaFunctionOperations,
  binjaProcedureIdentity,
} from "./BinjaFunctionOperations.js";
import {
  BinjaInventoryOperations,
  binjaSearchSchema,
} from "./BinjaInventoryOperations.js";
import type { BinjaMcpConnection } from "./BinjaMcpConnection.js";
import { binjaAddressSchema } from "./BinjaProtocolValues.js";
import type { BinjaOperation } from "./BinjaProviderCapabilities.js";
import { BinjaToolReader } from "./BinjaToolReader.js";

type Parameters = Readonly<Record<string, JsonValue>>;

const optionalAddress = (parameters: Parameters): string | undefined =>
  parameters.address === undefined
    ? undefined
    : binjaAddressSchema.parse(parameters.address);

/** Translate one analyst question into a closed set of read-only requests. */
export class BinjaOperationRunner {
  readonly reader: BinjaToolReader;
  readonly #functions: BinjaFunctionOperations;
  readonly #inventory: BinjaInventoryOperations;

  constructor(
    connection: BinjaMcpConnection,
    private readonly target: BinaryTarget,
    signal?: AbortSignal,
  ) {
    this.reader = new BinjaToolReader(connection, signal);
    this.#functions = new BinjaFunctionOperations(this.reader);
    this.#inventory = new BinjaInventoryOperations(
      this.reader,
      this.#functions,
    );
  }

  run(operation: BinjaOperation, parameters: Parameters): Promise<JsonValue> {
    switch (operation) {
      case "list_documents":
        // The session is bound to one target; its admitted path names it.
        return Promise.resolve([this.target.path]);
      case "list_procedures":
        return this.#inventory.procedures();
      case "search_procedures":
        return this.#inventory.procedures(binjaSearchSchema.parse(parameters));
      case "list_strings":
      case "search_strings":
      case "list_names":
      case "list_segments":
        return this.#inventoryOperation(operation, parameters);
      case "address_name":
      case "comment":
      case "read_bytes":
      case "address_to_file_offset":
      case "resolve_containing_procedure":
      case "xrefs":
        return this.#addressOperation(operation, parameters);
      default:
        return this.#functionOperation(operation, parameters);
    }
  }

  async #inventoryOperation(
    operation:
      | "list_strings"
      | "search_strings"
      | "list_names"
      | "list_segments",
    parameters: Parameters,
  ): Promise<JsonValue> {
    const address = optionalAddress(parameters);
    switch (operation) {
      case "list_strings":
        return this.#inventory.strings(
          address === undefined ? {} : { address },
        );
      case "search_strings":
        return this.#inventory.strings({
          query: binjaSearchSchema.parse(parameters),
        });
      case "list_names":
        return this.#inventory.names(address);
      case "list_segments":
        return this.#inventory.segments();
    }
  }

  async #addressOperation(
    operation:
      | "address_name"
      | "comment"
      | "read_bytes"
      | "address_to_file_offset"
      | "resolve_containing_procedure"
      | "xrefs",
    parameters: Parameters,
  ): Promise<JsonValue> {
    const address = binjaAddressSchema.parse(parameters.address);
    this.reader.locations.push({ kind: "address", address });
    switch (operation) {
      case "address_name":
        return this.#inventory.addressName(address);
      case "comment":
        return this.#inventory.comment(address);
      case "read_bytes":
        return this.#inventory.readBytes(
          address,
          z.number().int().min(1).parse(parameters.length),
        );
      case "address_to_file_offset":
        return this.#inventory.fileOffset(address);
      case "resolve_containing_procedure":
        return this.#inventory.containing(address);
      case "xrefs":
        return this.#inventory.xrefs(address);
    }
  }

  async #functionOperation(
    operation: Exclude<
      BinjaOperation,
      | "list_documents"
      | "list_procedures"
      | "search_procedures"
      | "list_strings"
      | "search_strings"
      | "list_names"
      | "list_segments"
      | "address_name"
      | "comment"
      | "read_bytes"
      | "address_to_file_offset"
      | "resolve_containing_procedure"
      | "xrefs"
    >,
    parameters: Parameters,
  ): Promise<JsonValue> {
    const fn = await this.#functions.resolve(
      z.string().min(1).parse(parameters.procedure),
    );
    this.reader.locations.push({ kind: "address", address: fn.address });
    switch (operation) {
      case "procedure_address":
        return fn.address;
      case "procedure_info":
        return this.#functions.info(fn);
      case "procedure_pseudo_code":
        return this.#functions.pseudocode(fn);
      case "procedure_assembly":
        return (await this.#functions.assembly(fn)).join("\n");
      case "procedure_callers":
        return (await this.#functions.callers(fn)).map(
          ({ address }) => address,
        );
      case "procedure_callees":
        return (await this.#functions.callees(fn)).resolved.map(
          ({ address }) => address,
        );
      case "procedure_references": {
        const direction = z
          .enum(["incoming", "outgoing"])
          .parse(parameters.direction);
        const { edges, unresolved } = await this.#functions.references(
          fn,
          direction,
        );
        return {
          procedure: binjaProcedureIdentity(fn),
          direction,
          reference_kinds_available: false,
          unresolved_calls: unresolved,
          references: edges,
        };
      }
      case "read_function_instructions":
        return this.#functions.instructions(fn);
      case "analyze_function":
        return this.#functions.dossier(fn);
    }
  }
}
