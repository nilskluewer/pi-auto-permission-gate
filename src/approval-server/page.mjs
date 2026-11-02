import fs from "node:fs";

// Assets stay inline because the page CSP permits no external scripts or styles.
export function loadPage() {
	/** @param {string} name */
	const read = (name) => fs.readFileSync(new URL(`./page/${name}`, import.meta.url), "utf8");
	return read("index.html")
		.trimEnd()
		.replace("/* STYLES */", () => read("styles.css"))
		.replace("/* SCRIPTS */", () => ["cards.js", "history.js", "app.js"].map(read).join("\n"));
}
