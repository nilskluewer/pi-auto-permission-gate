import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";

const SECRET =
	/^(?:\.env(?:\..*)?|id_(?:rsa|ed25519|ecdsa)(?:\.pub)?|credentials(?:\..*)?|auth\.json|approval-(?:queue\.json|history\.jsonl)|.*\.(?:pem|key|p12|pfx))$/i;
export const sensitivePath = (path: string): boolean =>
	SECRET.test(basename(path)) || /(?:^|\/)(?:\.ssh|\.aws|\.azure|\.kube)(?:\/|$)|\/\.config\/gcloud\//.test(path);
const hash = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");

export async function readRegularFile(path: string, maxBytes: number): Promise<{ content: string; digest: string }> {
	const file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
	try {
		const info = await file.stat();
		if (!info.isFile()) throw new Error("not a regular file");
		if (info.size > maxBytes) throw new Error("inspection byte limit exceeded");
		// Bound the actual read too: a file can grow after stat().
		const buffer = Buffer.alloc(maxBytes + 1);
		let size = 0;
		while (size < buffer.length) {
			const { bytesRead } = await file.read(buffer, size, buffer.length - size, null);
			if (!bytesRead) break;
			size += bytesRead;
		}
		if (size > maxBytes) throw new Error("inspection byte limit exceeded");
		const bytes = buffer.subarray(0, size);
		if (bytes.includes(0)) throw new Error("binary file; code was not inspected");
		return { content: bytes.toString("utf8"), digest: hash(bytes) };
	} finally {
		await file.close();
	}
}

export function localPath(value: string, cwd: string): string {
	return resolve(cwd, value === "~" ? homedir() : value.startsWith("~/") ? join(homedir(), value.slice(2)) : value);
}
