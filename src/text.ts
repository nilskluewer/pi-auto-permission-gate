import { MAX_PREVIEW_LENGTH } from "./constants.ts";

export function truncate(value: string, maxLength: number): string {
	return value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;
}

export function preview(command: string): string {
	return truncate(command, MAX_PREVIEW_LENGTH);
}

export function unique(values: string[]): string[] {
	return [...new Set(values)];
}
