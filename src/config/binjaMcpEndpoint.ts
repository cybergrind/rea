import { z } from "zod";

/** Default deadline for one Binary Ninja MCP request; large functions decompile slowly. */
export const DEFAULT_BINJA_MCP_TIMEOUT_MS = 900_000;

// Node schedules delays above this signed 32-bit boundary as a 1 ms timer.
const MAX_TIMER_DELAY_MS = 2_147_483_647;

/**
 * A caller-selected Binary Ninja MCP endpoint.
 *
 * The attached GUI serves unauthenticated Streamable HTTP, so only a literal
 * loopback host is admitted; credentials, queries, and fragments are rejected
 * rather than silently dropped.
 */
export const binjaMcpUrlSchema = z.string().refine((value) => {
  if (!URL.canParse(value)) return false;
  const url = new URL(value);
  return (
    ["http:", "https:"].includes(url.protocol) &&
    ["127.0.0.1", "[::1]"].includes(url.hostname) &&
    url.username === "" &&
    url.password === "" &&
    url.search === "" &&
    url.hash === ""
  );
}, "REA_BINJA_MCP_URL must be an absolute http(s) URL on a literal loopback host (127.0.0.1 or [::1]) without credentials, query, or fragment");

/** Parse the optional request deadline without reading the ambient environment. */
export const binjaMcpTimeoutSchema = z
  .string()
  .regex(/^[1-9]\d*$/u, "must be a positive decimal integer")
  .transform(Number)
  .pipe(z.number().int().min(1).max(MAX_TIMER_DELAY_MS))
  .default(DEFAULT_BINJA_MCP_TIMEOUT_MS);
