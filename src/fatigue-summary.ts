import type { Dirent } from "node:fs";
import { type FileHandle, open, readdir } from "node:fs/promises";
import { join } from "node:path";

interface DecisionRange {
	from?: number;
	to?: number;
}
interface Decision {
	[field: string]: unknown;
	timestamp?: number;
	source?: unknown;
	status?: unknown;
	shownAt?: unknown;
	answeredAt?: unknown;
	recommendation?: unknown;
}
interface FatigueSummary {
	total: number;
	autoApproved: number;
	autoBlocked: number;
	hardDenied: number;
	grantCovered: number;
	ruleDecisions: number;
	prompts: number;
	approved: number;
	denied: number;
	redirected: number;
	expired: number;
	legacyBlocked: number;
	activeHours: number;
	promptsPerActiveHour: number;
	steerOrDenyRate: number;
	expiryRate: number;
	disagreement: number;
	medianAnswerMs?: number;
}

const STATUSES = new Set<unknown>(["approved", "blocked", "redirected", "expired"]);
const SOURCES = new Set<unknown>(["hard-deny", "auto-model", "user-rule", "human", "intent-grant"]);
const NEW_FIELDS = ["recommendation", "shownAt", "answeredAt", "scope", "grantId", "note"];

function finiteNumber(value: unknown): value is number {
	return Number.isFinite(value);
}

function objectRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object";
}

/** Read root files and files in immediate subfolders. Range bounds are inclusive. */
export async function readSessionDecisions(sessionsDir: string, range: DecisionRange = {}): Promise<Decision[]> {
	const decisions: Decision[] = [];
	async function walk(directory: string, descend: boolean): Promise<void> {
		let files: Dirent[];
		try {
			files = await readdir(directory, { withFileTypes: true });
		} catch (error) {
			if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
			throw error;
		}
		files.sort((a, b) => a.name.localeCompare(b.name));
		for (const file of files) {
			const path = join(directory, file.name);
			if (file.isDirectory() && descend) {
				await walk(path, false);
			} else if (file.isFile() && file.name.endsWith(".jsonl")) {
				await readFileDecisions(path);
			}
		}
	}
	async function readFileDecisions(path: string): Promise<void> {
		let handle: FileHandle | undefined;
		try {
			handle = await open(path, "r");
			for await (const line of handle.readLines()) {
				let record: unknown;
				try {
					record = JSON.parse(line);
				} catch {
					// Session files can contain partial or malformed lines.
					continue;
				}
				if (
					!record ||
					typeof record !== "object" ||
					!("type" in record) ||
					record.type !== "custom" ||
					!("customType" in record) ||
					record.customType !== "permission-gate-decision"
				)
					continue;
				const data = "data" in record ? record.data : undefined;
				if (!objectRecord(data) || !STATUSES.has(data.status) || !SOURCES.has(data.source)) continue;
				const timestamp =
					data.timestamp ?? Date.parse(("timestamp" in record ? record.timestamp : undefined) as string);
				if (!finiteNumber(timestamp)) continue;
				if (range.from !== undefined && timestamp < range.from) continue;
				if (range.to !== undefined && timestamp > range.to) continue;
				decisions.push({ ...data, timestamp });
			}
		} catch (error) {
			// A session can disappear while the report reads the directory.
			if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
		} finally {
			await handle?.close();
		}
	}
	await walk(sessionsDir, true);
	return decisions;
}

/** Keep old blocks separate: they do not prove that the user answered. */
export function summarizeDecisions(entries: Decision[]): FatigueSummary {
	const summary: FatigueSummary = {
		total: entries.length,
		autoApproved: 0,
		autoBlocked: 0,
		hardDenied: 0,
		grantCovered: 0,
		ruleDecisions: 0,
		prompts: 0,
		approved: 0,
		denied: 0,
		redirected: 0,
		expired: 0,
		legacyBlocked: 0,
		activeHours: 0,
		promptsPerActiveHour: 0,
		steerOrDenyRate: 0,
		expiryRate: 0,
		disagreement: 0,
	};
	const hours = new Set();
	const delays: number[] = [];
	for (const entry of entries) {
		if (finiteNumber(entry.timestamp)) hours.add(Math.floor(entry.timestamp / 3_600_000));
		if (entry.source === "auto-model") {
			if (entry.status === "approved") summary.autoApproved++;
			if (entry.status === "blocked") summary.autoBlocked++;
		} else if (entry.source === "hard-deny") {
			summary.hardDenied++;
		} else if (entry.source === "intent-grant") {
			summary.grantCovered++;
		} else if (entry.source === "user-rule") {
			summary.ruleDecisions++;
		}
		if (finiteNumber(entry.shownAt) && finiteNumber(entry.answeredAt) && entry.answeredAt >= entry.shownAt) {
			delays.push(entry.answeredAt - entry.shownAt);
		}
		if (entry.source !== "human") continue;
		summary.prompts++;
		const legacy = entry.status === "blocked" && NEW_FIELDS.every((field) => entry[field] === undefined);
		if (entry.status === "approved") summary.approved++;
		if (entry.status === "blocked") {
			if (legacy) summary.legacyBlocked++;
			else summary.denied++;
		}
		if (entry.status === "redirected") summary.redirected++;
		if (entry.status === "expired") summary.expired++;
		const answered =
			!legacy && (entry.status === "approved" || entry.status === "blocked" || entry.status === "redirected");
		if (
			answered &&
			((entry.recommendation === "approve" && entry.status !== "approved") ||
				(entry.recommendation === "deny" && entry.status === "approved"))
		)
			summary.disagreement++;
	}
	summary.activeHours = hours.size;
	summary.promptsPerActiveHour = hours.size ? summary.prompts / hours.size : 0;
	const answers = summary.approved + summary.denied + summary.redirected;
	summary.steerOrDenyRate = answers ? (summary.denied + summary.redirected) / answers : 0;
	summary.expiryRate = summary.prompts ? summary.expired / summary.prompts : 0;
	if (delays.length) {
		delays.sort((a, b) => a - b);
		const middle = Math.floor(delays.length / 2);
		summary.medianAnswerMs = delays.length % 2 ? delays[middle] : (delays[middle - 1] + delays[middle]) / 2;
	}
	return summary;
}

export function formatFatigueSummary(summary: FatigueSummary, range: DecisionRange = {}): string {
	const percent = (value: number): string => `${(value * 100).toFixed(1)}%`;
	const answerCount = summary.approved + summary.denied + summary.redirected;
	const answerRate = (count: number): string => percent(answerCount ? count / answerCount : 0);
	const lines = ["Approval fatigue summary"];
	if (range.from !== undefined || range.to !== undefined) {
		const from = range.from === undefined ? "start" : new Date(range.from).toISOString();
		const to = range.to === undefined ? "now" : new Date(range.to).toISOString();
		lines.push(`Range (UTC): ${from} to ${to}`);
	}
	lines.push(
		`Decisions: ${summary.total}`,
		`Auto-approved: ${summary.autoApproved}; auto-blocked: ${summary.autoBlocked}; hard-denied: ${summary.hardDenied}`,
		`Rule decisions: ${summary.ruleDecisions}; Grant-covered: ${summary.grantCovered} (prompts saved)`,
		`Prompts: ${summary.prompts}; active hours (UTC): ${summary.activeHours}`,
		`Prompts per active hour: ${summary.promptsPerActiveHour.toFixed(2)}`,
		`Approved: ${summary.approved}; Denied: ${summary.denied}; Redirected: ${summary.redirected}; Expired: ${summary.expired}`,
		`Denial rate: ${answerRate(summary.denied)}; redirect rate: ${answerRate(summary.redirected)} (known answers)`,
		`Steer-or-deny rate: ${percent(summary.steerOrDenyRate)}; expiry rate: ${percent(summary.expiryRate)}`,
		`Legacy blocks: ${summary.legacyBlocked} (may include timeouts; excluded from denials)`,
		`Median answer time: ${summary.medianAnswerMs === undefined ? "not available" : `${summary.medianAnswerMs} ms`}`,
		`Classifier disagreements: ${summary.disagreement}`,
		`${summary.promptsPerActiveHour < 3 ? "✓" : "✗"} Target: <3 prompts per active hour`,
		`${summary.steerOrDenyRate >= 0.15 ? "✓" : "✗"} Target: ≥15% steer-or-deny rate`,
	);
	return lines.join("\n");
}
