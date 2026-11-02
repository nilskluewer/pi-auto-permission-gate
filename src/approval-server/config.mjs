export const MAX_BODY = 64 * 1024;
export const MAX_PENDING = 200;
export const KEEP_RESOLVED_MS = 2 * 60 * 1000;
export const DEFAULT_TTL_MS = 10 * 60 * 1000;
export const MAX_TTL_MS = 60 * 60 * 1000;
export const MAX_WAIT_MS = 30_000;
export const HEARTBEAT_MS = 15_000;
export const OPEN_DEBOUNCE_MS = 15_000;
export const IDLE_MS = Number(process.env.APPROVAL_IDLE_MS) > 0 ? Number(process.env.APPROVAL_IDLE_MS) : 20 * 60 * 1000;
export const TEST_TOKEN = process.env.APPROVAL_TEST_APPROVER_TOKEN || "";
export const MIN_TTL_MS = TEST_TOKEN ? 100 : 10_000;
export const NO_OPEN = process.env.APPROVAL_NO_OPEN === "1";
/** @param {string | undefined} v @param {number} d */
export const posInt = (v, d) => (Number.isInteger(Number(v)) && Number(v) > 0 ? Number(v) : d);
export const HISTORY_KEEP = posInt(process.env.APPROVAL_HISTORY_KEEP, 500);
export const HISTORY_MAX_LINES = posInt(process.env.APPROVAL_HISTORY_MAX_LINES, 2000);
export const HISTORY_SNAPSHOT = 200;
export const HISTORY_RATE_LIMIT = 200;
export const HISTORY_RATE_WINDOW_MS = 10_000;
export const DAY_MS = 24 * 60 * 60 * 1000;

