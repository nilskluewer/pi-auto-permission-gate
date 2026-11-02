import { basename } from "node:path";
import { shellWords } from "./shell-words.ts";

export type Environment = "production" | "non-production" | "unknown";
export interface Criticality {
	critical: boolean;
	criticalReasons: string[];
	grantableReasons: string[];
	environment?: Environment;
	accessChange: boolean;
}

export const DEFAULT_PRODUCTION_PATTERNS = ["prod", "prd", "production"];
export const NON_PRODUCTION_MARKERS = [
	"dev",
	"development",
	"test",
	"testing",
	"sandbox",
	"sbx",
	"stage",
	"staging",
	"stg",
	"int",
	"qa",
	"local",
	"demo",
];
export const ALWAYS_CRITICAL_REASONS = ["sudo", "disk shred/wipe", "partition editor"];

const ENVIRONMENT_FLAG = /^--(?:project|project-id|context|namespace|profile|subscription|resource-group)(?:=(.*))?$/;

export function environmentIdentifiers(command: string): string[] {
	const words = shellWords(command.toLowerCase());
	const identifiers = new Set<string>();
	for (let i = 0; i < words.length; i++) {
		const word = words[i];
		const flag = ENVIRONMENT_FLAG.exec(word);
		if (flag) {
			const value = flag[1] ?? words[++i];
			if (value && !/^[;&|<>()\n-]/.test(value)) identifiers.add(value);
			continue;
		}
		const bucket = /^(?:gs|s3):\/\/([^/]+)/.exec(word);
		if (bucket) {
			identifiers.add(bucket[1]);
			continue;
		}
		if (word.startsWith("-") || word.includes("=") || /\s/.test(word)) continue;
		// These names can also occur without an environment flag.
		if (/^[a-z\d][a-z\d_.:/@-]*$/.test(word)) {
			if (NON_PRODUCTION_MARKERS.includes(word) || DEFAULT_PRODUCTION_PATTERNS.includes(word) || /[-_.:/@]/.test(word))
				identifiers.add(word);
			if (words.includes("bq") && /[.:]/.test(word)) identifiers.add(word.split(/[.:]/)[0]);
		}
		if (
			(words[i - 1] === "use-context" ||
				(words[i - 2] === "workspace" && /^(?:select|new|delete)$/.test(words[i - 1]))) &&
			word
		)
			identifiers.add(word);
	}
	return [...identifiers];
}

function globExpression(pattern: string): RegExp {
	let expression = "";
	for (const char of pattern) {
		if (char === "*") expression += ".*";
		else if (char === "?") expression += ".";
		else expression += char.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	}
	return new RegExp(`^${expression}$`, "i");
}

export function classifyEnvironment(
	command: string,
	productionPatterns: string[] = DEFAULT_PRODUCTION_PATTERNS,
): Environment {
	const values = environmentIdentifiers(command).flatMap((id) => [id, ...id.split(/[-_.:/@]/)]);
	const production = productionPatterns.map(globExpression);
	if (values.some((value) => production.some((pattern) => pattern.test(value)))) return "production";
	if (values.some((value) => NON_PRODUCTION_MARKERS.includes(value))) return "non-production";
	return "unknown";
}

const GLOBAL_VALUE_FLAGS = new Set([
	"--project",
	"--project-id",
	"--context",
	"--namespace",
	"--profile",
	"--subscription",
	"--resource-group",
	"--region",
	"--zone",
	"--account",
	"--configuration",
	"--output",
	"--query",
	"--format",
	"--endpoint-url",
	"--verbosity",
]);

export function isAccessChange(command: string): boolean {
	const raw = shellWords(command.toLowerCase());
	if (raw.some((word) => /^(?:set-iam-policy|add-iam-policy-binding|remove-iam-policy-binding)$/.test(word)))
		return true;
	if (raw.some((word) => /^--impersonate-service-account(?:=|$)/.test(word))) return true;
	const words = [];
	for (let i = 0; i < raw.length; i++) {
		if (GLOBAL_VALUE_FLAGS.has(raw[i])) {
			i++;
			continue;
		}
		if (
			raw[i].startsWith("--") &&
			(raw[i].includes("=") || /^(?:--quiet|--debug|--no-cli-pager|--no-paginate)$/.test(raw[i]))
		)
			continue;
		words.push(raw[i]);
	}
	const text = words.join(" ");
	if (
		/\biam service-accounts (?:create|keys create)\b|\biam roles (?!list\b|describe\b)\S+|\bauth (?:application-default )?print-(?:access|identity)-token\b/.test(
			text,
		)
	)
		return true;
	if (/\baz role assignment (?:create|delete)\b/.test(text)) return true;
	for (let i = 0; i < words.length; i++) {
		if (basename(words[i]) === "aws") {
			const end = words.findIndex((word, index) => index > i && /^[;&|()\n]$/.test(word));
			const segment = words.slice(i, end < 0 ? undefined : end);
			const iam = segment.indexOf("iam");
			if (iam >= 0 && segment[iam + 1] && !/^(?:list|get|describe|simulate)(?:-|$)/.test(segment[iam + 1])) return true;
		}
	}
	return /\bkubectl\b[^;&|\n]*\b(?:create|apply)\b[^;&|\n]*\b(?:cluster)?rolebindings?\b/.test(text);
}

export function assessCriticality(
	command: string,
	reasons: string[],
	options: { productionPatterns?: string[] } = {},
): Criticality {
	const environment = reasons.includes("cloud or infrastructure change")
		? classifyEnvironment(command, options.productionPatterns)
		: undefined;
	const accessChange = isAccessChange(command);
	const criticalReasons: string[] = [],
		grantableReasons: string[] = [];
	for (const reason of reasons) {
		const critical =
			ALWAYS_CRITICAL_REASONS.includes(reason) ||
			reason === "Pi or gate configuration write" ||
			(reason === "cloud or infrastructure change" && (accessChange || environment !== "non-production"));
		(critical ? criticalReasons : grantableReasons).push(reason);
	}
	return {
		critical: criticalReasons.length > 0,
		criticalReasons,
		grantableReasons,
		...(environment === undefined ? {} : { environment }),
		accessChange,
	};
}
