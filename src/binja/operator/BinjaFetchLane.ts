import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { z } from "zod";

/** A queue line, envelope, or analysis call the lane could not use. */
export class BinjaFetchError extends Error {}

/** One queued function: pseudocode alone, or the whole dossier when `full`. */
export interface BinjaFetchRequest {
  /** Canonical lowercase `0x` entry address. */
  readonly address: string;
  readonly full: boolean;
}

/** The public REA command that answers one request. */
export const fetchCommand = (request: BinjaFetchRequest): string =>
  request.full ? "function" : "decompile";

/**
 * Parse queue text: one hexadecimal address per line, `0x` optional, with the
 * rest of the line and `#` lines as comments. `full <addr>` asks for the
 * dossier. An address appears once, a `full` request replacing a plain one,
 * and cheap plain requests come first.
 */
export const parseFetchQueue = (text: string): BinjaFetchRequest[] => {
  const seen = new Map<string, boolean>();
  text.split(/\r?\n/u).forEach((raw, index) => {
    const tokens = (raw.split("#", 1)[0] ?? "").trim().split(/\s+/u);
    if (tokens[0] === undefined || tokens[0] === "") return;
    const full = tokens[0] === "full";
    const token = (full ? tokens[1] : tokens[0]) ?? "";
    if (!/^(?:0x)?[0-9a-f]+$/iu.test(token))
      throw new BinjaFetchError(
        `line ${String(index + 1)}: ${JSON.stringify(token)} is not a hex address`,
      );
    const address = `0x${BigInt(/^0x/iu.test(token) ? token : `0x${token}`).toString(16)}`;
    seen.set(address, (seen.get(address) ?? false) || full);
  });
  const requests = [...seen].map(([address, full]) => ({ address, full }));
  return [
    ...requests.filter(({ full }) => !full),
    ...requests.filter(({ full }) => full),
  ];
};

/** Read the queue file and every `*.txt` request file readers dropped. */
export const readFetchQueue = (
  queue: string | undefined,
  requests: string | undefined,
): BinjaFetchRequest[] => {
  const files = queue === undefined ? [] : [queue];
  if (requests !== undefined && existsSync(requests))
    files.push(
      ...readdirSync(requests)
        .filter((name) => name.endsWith(".txt"))
        .sort()
        .map((name) => join(requests, name)),
    );
  return parseFetchQueue(
    files
      .filter((path) => existsSync(path))
      .map((path) => readFileSync(path, "utf8"))
      .join("\n"),
  );
};

const dossierSchema = z.looseObject({
  pseudocode: z.string(),
  assembly: z.array(z.string()).default([]),
  callers: z.array(z.looseObject({ address: z.string(), name: z.string() })),
  callees: z.array(z.looseObject({ address: z.string(), name: z.string() })),
  unresolved_calls: z.array(z.looseObject({ address: z.string() })).default([]),
  outgoing_references: z
    .array(
      z.looseObject({
        source_address: z.string(),
        target_address: z.string(),
        target_procedure: z.unknown(),
      }),
    )
    .default([]),
});
type Dossier = z.infer<typeof dossierSchema>;

/**
 * Call edges for offline readers. A call site whose target is not an analyzed
 * function (an import slot, for example) is listed by its target address in
 * place of a name, after the resolved callees.
 */
const callEdges = (dossier: Dossier): string => {
  const unresolved = new Set(
    dossier.unresolved_calls.map(({ address }) => address),
  );
  const bare = new Set(
    dossier.outgoing_references
      .filter(
        (edge) =>
          edge.target_procedure === null && unresolved.has(edge.source_address),
      )
      .map(({ target_address }) => target_address),
  );
  return [
    ...dossier.callers.map((edge) => `caller ${edge.address} ${edge.name}\n`),
    ...dossier.callees.map((edge) => `callee ${edge.address} ${edge.name}\n`),
    ...[...bare].map((address) => `callee ${address} ${address}\n`),
  ].join("");
};
const envelopeSchema = z.looseObject({
  provider: z.looseObject({ id: z.string() }),
  normalized_result: z.union([z.string(), dossierSchema]),
});

const failureSchema = z.looseObject({ error: z.string() });

/** Evidence directories and the one call that produces an Evidence envelope. */
export interface BinjaFetchLaneOptions {
  /** Run the analysis for one request and return the CLI's JSON output. */
  readonly run: (request: BinjaFetchRequest) => Promise<string>;
  /** Evidence envelopes: `<command>-<addr>.json` and `.err` markers. */
  readonly jsonDir: string;
  /** Extracted text: `0x<addr>-REA.c`, `.asm`, `.calls.txt`. */
  readonly codeDir: string;
  readonly log?: (line: string) => void;
}

/** Create a file that does not exist yet; saved evidence is never replaced. */
const writeNew = (path: string, content: string): boolean => {
  try {
    writeFileSync(path, content, { flag: "wx" });
    return true;
  } catch (cause: unknown) {
    if (cause instanceof Error && "code" in cause && cause.code === "EEXIST")
      return false;
    throw cause;
  }
};

/** Write an envelope under the first unused name: a new read gets a new file. */
const writeEnvelope = (stem: string, text: string): string => {
  for (let attempt = 1; ; attempt += 1) {
    const path =
      attempt === 1 ? `${stem}.json` : `${stem}.${String(attempt)}.json`;
    if (writeNew(path, text)) return path;
  }
};

/** Fetches queued functions one at a time and saves them as offline evidence. */
export class BinjaFetchLane {
  constructor(private readonly options: BinjaFetchLaneOptions) {}

  /** A request is done once its last output file exists under any label. */
  saved(request: BinjaFetchRequest): boolean {
    const suffix = request.full ? ".calls.txt" : ".c";
    return (
      existsSync(this.options.codeDir) &&
      readdirSync(this.options.codeDir).some(
        (name) =>
          name.startsWith(`${request.address}-`) && name.endsWith(suffix),
      )
    );
  }

  /** Fetch one request; a failure leaves an `.err` marker and throws. */
  async fetch(request: BinjaFetchRequest): Promise<void> {
    const { jsonDir, codeDir } = this.options;
    mkdirSync(jsonDir, { recursive: true });
    mkdirSync(codeDir, { recursive: true });
    const stem = join(
      jsonDir,
      `${fetchCommand(request)}-${request.address.slice(2)}`,
    );
    let text: string;
    let result: z.infer<typeof envelopeSchema>["normalized_result"];
    try {
      text = await this.options.run(request);
      const output: unknown = JSON.parse(text);
      // REA prints an analysis failure as a JSON object carrying `error`.
      if (failureSchema.safeParse(output).success)
        throw new BinjaFetchError(`rea reported ${text.trim().slice(0, 2000)}`);
      result = envelopeSchema.parse(output).normalized_result;
      if ((typeof result === "string") === request.full)
        throw new BinjaFetchError("envelope does not answer this request");
      const code = typeof result === "string" ? result : result.pseudocode;
      if (code.trim() === "")
        throw new BinjaFetchError("envelope has no pseudocode");
    } catch (cause: unknown) {
      const reason = cause instanceof Error ? cause.message : String(cause);
      writeFileSync(`${stem}.err`, `${reason}\n`);
      throw new BinjaFetchError(reason, { cause });
    }
    writeEnvelope(stem, text);
    const out = join(codeDir, `${request.address}-REA`);
    const code = typeof result === "string" ? result : result.pseudocode;
    if (!writeNew(`${out}.c`, code))
      this.options.log?.(`${request.address} kept its saved pseudocode`);
    if (typeof result === "string") return;
    writeNew(`${out}.asm`, result.assembly.map((line) => `${line}\n`).join(""));
    writeNew(`${out}.calls.txt`, callEdges(result));
  }
}

/** Why a lane run ended, with the addresses it could not fetch. */
export interface BinjaFetchLaneOutcome {
  readonly status: "idle" | "stopped";
  readonly fetched: readonly string[];
  readonly failed: readonly string[];
}

/** Inputs of one lane run; time is injected so the loop stays testable. */
export interface BinjaFetchRunOptions {
  readonly lane: BinjaFetchLane;
  /** Re-read before every call so a cheap request never waits behind a dossier. */
  readonly readQueue: () => BinjaFetchRequest[];
  /** Keep serving new requests until idle for this long. */
  readonly watchMs: number;
  readonly pollMs?: number;
  /** Stop instead of hammering a wedged backend. */
  readonly maxConsecutiveFailures?: number;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly log?: (line: string) => void;
  readonly signal?: AbortSignal;
}

/**
 * Drain the queue strictly one request at a time until it stays empty for
 * `watchMs`, or stop after consecutive failures. A failed address is not
 * retried within the run.
 */
export const runBinjaFetchLane = async (
  options: BinjaFetchRunOptions,
): Promise<BinjaFetchLaneOutcome> => {
  const now = options.now ?? Date.now;
  const sleep =
    options.sleep ??
    ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const limit = options.maxConsecutiveFailures ?? 3;
  const fetched: string[] = [];
  const failed = new Set<string>();
  let streak = 0;
  let idleSince = now();
  while (options.signal?.aborted !== true) {
    const next = options
      .readQueue()
      .find(
        (request) =>
          !failed.has(request.address) && !options.lane.saved(request),
      );
    if (next === undefined) {
      if (now() - idleSince >= options.watchMs) break;
      await sleep(options.pollMs ?? 5000);
      continue;
    }
    try {
      await options.lane.fetch(next);
      fetched.push(next.address);
      streak = 0;
      options.log?.(`${next.address} saved`);
    } catch (cause: unknown) {
      if (!(cause instanceof BinjaFetchError)) throw cause;
      failed.add(next.address);
      streak += 1;
      options.log?.(`${next.address} failed: ${cause.message}`);
      if (streak >= limit)
        return { status: "stopped", fetched, failed: [...failed] };
    }
    idleSince = now();
  }
  return { status: "idle", fetched, failed: [...failed] };
};
