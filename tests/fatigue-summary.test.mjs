import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { formatFatigueSummary, readSessionDecisions, summarizeDecisions } from "../src/fatigue-summary.mjs";

const fixtures = fileURLToPath(new URL("./fixtures/fatigue-sessions/", import.meta.url));

// Oracle: shared contract D. These values come from the fixture records, not the code.
// 4 root records + 8 project records = 12. Sources: auto 2, hard 1, rule 2,
// grant 1, human 6. Human: approve 2, deny 1, redirect 1, expire 1, legacy 1.
// Hours: Oct 21 at 09, 10, 11 UTC = 3. Prompts/hour = 6/3 = 2.
// Steer/deny = (1+1)/(2+1+1) = 1/2. Expiry = 1/6, not a denial.
// Answer delays: 1000, 3000, 5000, 7000 ms; median = (3000+5000)/2 = 4000.
// Disagreements: deny -> approve, approve -> deny, approve -> redirect = 3.
const expected = {
	total: 12,
	autoApproved: 1,
	autoBlocked: 1,
	hardDenied: 1,
	grantCovered: 1,
	ruleDecisions: 2,
	prompts: 6,
	approved: 2,
	denied: 1,
	redirected: 1,
	expired: 1,
	legacyBlocked: 1,
	activeHours: 3,
	promptsPerActiveHour: 2,
	steerOrDenyRate: 0.5,
	expiryRate: 1 / 6,
	medianAnswerMs: 4000,
	disagreement: 3,
};

test("reads root and one child level; ignores malformed and unrelated records", async () => {
	const entries = await readSessionDecisions(fixtures);
	assert.equal(entries.length, 12);
	assert.equal(entries.filter((entry) => entry.source === "human").length, 6);
	assert.equal(entries.find((entry) => entry.command === "human redirect").note, "Use uv");
	assert.ok(entries.every((entry) => typeof entry.timestamp === "number"));
});

test("keeps expiry and legacy blocks out of denials and answer disagreements", async () => {
	assert.deepEqual(summarizeDecisions(await readSessionDecisions(fixtures)), expected);
});

test("filters inclusively by decision time, not the wrapper timestamp", async () => {
	// The first two root entries are exactly at the range boundaries.
	const entries = await readSessionDecisions(fixtures, { from: 1792573200000, to: 1792573260000 });
	assert.deepEqual(entries.map((entry) => entry.command).sort(), ["auto allow", "auto block"]);
	assert.equal((await readSessionDecisions(fixtures, { to: 1792573199999 })).length, 0);
	assert.equal((await readSessionDecisions(fixtures, { from: 1792580760000 })).length, 1);
	assert.deepEqual(await readSessionDecisions(`${fixtures}/does-not-exist`), []);
});

test("does not read deeper folders or non-jsonl files", async () => {
	assert.equal((await readSessionDecisions(fixtures)).length, 12);
});

test("empty summaries have zero rates and no answer median", () => {
	const summary = summarizeDecisions([]);
	assert.deepEqual(summary, {
		total: 0,
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
	});
	assert.doesNotMatch(formatFatigueSummary(summary), /NaN|Infinity|undefined/);
});

test("counts UTC date-hour pairs, not hours of day or elapsed time", () => {
	// The same hour on two dates is two active hours, not one or 25.
	const entries = [1792573200000, 1792659600000].map((timestamp) => ({
		source: "human",
		status: "approved",
		timestamp,
	}));
	const summary = summarizeDecisions(entries);
	assert.equal(summary.activeHours, 2);
	assert.equal(summary.promptsPerActiveHour, 1);
});

test("uses odd medians and ignores invalid or negative answer durations", () => {
	// Valid delays 0, 2000, 9000 ms -> middle value 2000, not mean 3666.67.
	const entries = [0, 2000, 9000, -1, Infinity, "3000"].map((delay) => ({
		source: "human",
		status: "approved",
		timestamp: 1792573200000,
		shownAt: 0,
		answeredAt: delay,
	}));
	assert.equal(summarizeDecisions(entries).medianAnswerMs, 2000);
});

test("uses available timing fields without requiring a source label", () => {
	// Both records have timing fields: delays 1000 and 3000 -> median 2000 ms.
	const entries = [
		{ source: "human", status: "approved", shownAt: 0, answeredAt: 1000 },
		{ source: "auto-model", status: "approved", shownAt: 0, answeredAt: 3000 },
	];
	assert.equal(summarizeDecisions(entries).medianAnswerMs, 2000);
});

test("recognizes new blocked records without treating every old block as a denial", () => {
	const entries = [
		{ status: "blocked", recommendation: "review" },
		{ status: "blocked", answeredAt: 0 },
		{ status: "blocked" },
		{ status: "expired", recommendation: "approve" },
	].map((entry) => ({ source: "human", timestamp: 1792573200000, ...entry }));
	const summary = summarizeDecisions(entries);
	assert.equal(summary.denied, 2);
	assert.equal(summary.legacyBlocked, 1);
	assert.equal(summary.expired, 1);
	assert.equal(summary.disagreement, 0);
});

test("formats rates, outcomes, grant savings, range, and both success targets", () => {
	const report = formatFatigueSummary(expected, { from: 1792573200000, to: 1792580760000 });
	assert.match(report, /2026-10-21T09:00:00.000Z/);
	assert.match(report, /2026-10-21T11:06:00.000Z/);
	assert.match(report, /Prompts: 6/);
	assert.match(report, /Denied: 1/);
	assert.match(report, /Redirected: 1/);
	assert.match(report, /Expired: 1/);
	assert.match(report, /16\.7%/);
	assert.match(report, /50\.0%/);
	assert.match(report, /Grant-covered: 1/);
	assert.match(report, /Median answer time: 4000 ms/);
	assert.match(report, /✓[^\n]*<\s*3/);
	assert.match(report, /✓[^\n]*≥\s*15%/);
});

test("target markers enforce strict prompt limit and inclusive steer threshold", () => {
	// Exactly 3 fails <3. Exactly 15% passes >=15%; 14.9% fails.
	const boundary = formatFatigueSummary({ ...expected, promptsPerActiveHour: 3, steerOrDenyRate: 0.15 });
	assert.match(boundary, /✗[^\n]*<\s*3/);
	assert.match(boundary, /✓[^\n]*≥\s*15%/);
	assert.match(formatFatigueSummary({ ...expected, steerOrDenyRate: 0.149 }), /✗[^\n]*≥\s*15%/);
});
