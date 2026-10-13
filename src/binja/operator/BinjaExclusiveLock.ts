import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

/** Another process already holds the one-caller lock of this Binary Ninja. */
export class BinjaLockHeldError extends Error {
  constructor(readonly path: string) {
    super(
      `Another Binary Ninja caller holds ${path}. Binary Ninja answers one caller at a time; wait for it or stop it first.`,
    );
  }
}

/** A held lock; releasing it is idempotent. */
export interface BinjaLock {
  readonly path: string;
  release(): void;
}

const isBusy = (cause: unknown): boolean =>
  cause instanceof Error &&
  "errcode" in cause &&
  typeof cause.errcode === "number" &&
  // SQLITE_BUSY and SQLITE_LOCKED, with their extended codes.
  [5, 6].includes(cause.errcode & 0xff);

/**
 * Take the exclusive one-caller lock without waiting.
 *
 * SQLite owns acquisition and OS-backed release, including process death, so
 * a crashed holder never leaves a stale lock. The pathname must stay stable:
 * deleting the file while it is held would split its owners.
 */
export const acquireBinjaLock = (path: string): BinjaLock => {
  mkdirSync(dirname(path), { recursive: true });
  const database = new DatabaseSync(path, { timeout: 0 });
  try {
    database.exec("BEGIN EXCLUSIVE");
  } catch (cause: unknown) {
    database.close();
    if (isBusy(cause)) throw new BinjaLockHeldError(path);
    throw cause;
  }
  let held = true;
  return {
    path,
    release() {
      if (!held) return;
      held = false;
      database.close();
    },
  };
};
