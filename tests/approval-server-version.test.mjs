import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

test("server version includes browser assets and uses stable file order", async () => {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), "approval-version-"));
	try {
		const server = path.join(directory, "server");
		fs.cpSync(new URL("../src/approval-server/", import.meta.url), server, { recursive: true });
		const { approvalServerVersion } = await import(pathToFileURL(path.join(server, "version.mjs")).href);
		const before = approvalServerVersion();
		assert.equal(approvalServerVersion(), before);
		const asset = path.join(server, "page", "styles.css");
		const original = fs.readFileSync(asset);
		fs.appendFileSync(asset, "\n/* asset content */\n");
		assert.notEqual(approvalServerVersion(), before);
		fs.writeFileSync(asset, original);
		assert.equal(approvalServerVersion(), before);
	} finally {
		fs.rmSync(directory, { recursive: true, force: true });
	}
});
