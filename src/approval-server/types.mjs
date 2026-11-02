/**
 * Display data is validated at the HTTP boundary before it enters the queue.
 * @typedef {{path: string, role: string, inspected?: boolean, unresolved?: boolean}} DisplayPath
 * @typedef {{paths?: DisplayPath[], pathNotes?: string[]}} Inspection
 * @typedef {{label: string, access: string, reasons: string[], targets: string[]}} Intent
 * @typedef {Inspection & {
 * sessionId: string, sessionLabel: string, cwd: string, command: string,
 * risk: string, tldr: string, reasons: string[], kind: string,
 * recommendation: string, model?: string, via?: string, status?: string,
 * source?: string, note?: string, scope?: string, grantId?: string,
 * shownAt?: number, answeredAt?: number, ts?: number, id?: string,
 * ttlMs?: number, intentProposal?: Intent, intent?: Intent,
 * decision: string, confirm?: boolean
 * }} Body
 * @typedef {Inspection & {
 * sessionId: string, sessionLabel: string, cwd: string, command: string,
 * risk: string, tldr: string, reasons: string[], recommendation?: string,
 * model?: string, via?: string, status?: string, source?: string,
 * note?: string, scope?: string, grantId?: string, shownAt?: number,
 * answeredAt?: number, id?: string
 * }} HistoryFields
 * @typedef {HistoryFields & {id: string, ts: number}} HistoryEntry
 * @typedef {{res: import('node:http').ServerResponse, timer: ReturnType<typeof setTimeout> | null}} Waiter
 * @typedef {Inspection & {
 * id: string, sessionId: string, sessionLabel: string, cwd: string,
 * command: string, kind: string, risk: string, tldr: string,
 * recommendation: string, reasons: string[], model: string,
 * createdAt: number, expiresAt: number, status: string, parked: boolean,
 * intentProposal?: Intent, note?: string, scope?: string, intent?: Intent,
 * answeredAt?: number, expiryTimer?: ReturnType<typeof setTimeout>, waiters: Set<Waiter>
 * }} Request
 * @typedef {{note?: string, scope?: string, intent?: Intent}} Resolution
 * @typedef {{port: number, lastActivity: number}} Runtime
 * @typedef {(event: string, data: unknown) => void} Broadcast
 * @typedef {ReturnType<typeof import('./history.mjs').createHistory>} HistoryStore
 * @typedef {ReturnType<typeof import('./queue.mjs').createQueue>} Queue
 */
export {};
