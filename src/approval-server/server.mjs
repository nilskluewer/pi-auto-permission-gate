#!/usr/bin/env node
import path from "node:path";
import { startServer } from "./lifecycle.mjs";

const stateFile = process.argv[2];
if (!stateFile || !path.isAbsolute(stateFile)) {
	console.error("usage: node server.mjs <absolute-state-file-path>");
	process.exit(2);
}
startServer(stateFile).catch((e) => {
	console.error(`approval-server failed: ${e.message}`);
	process.exit(1);
});
