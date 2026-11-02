import crypto from "node:crypto";
import { MAX_BODY } from "./config.mjs";
/** @param {unknown} s */
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
/** @param {unknown} given @param {string} expected */
export const tokenOk = (given, expected) => typeof given === "string" && crypto.timingSafeEqual(sha(given), sha(expected));
/** @param {unknown} v @param {number} n */
export const clip = (v, n) => String(v).slice(0, n);

export const SECURITY_HEADERS = {
	"x-content-type-options": "nosniff",
	"cache-control": "no-store",
	"referrer-policy": "no-referrer",
};

/** @param {import('node:http').ServerResponse} res @param {number} status @param {unknown} body @param {import('node:http').OutgoingHttpHeaders} [extra] */
export function sendJson(res, status, body, extra) {
	const payload = JSON.stringify(body);
	res.writeHead(status, {
		...SECURITY_HEADERS,
		"content-type": "application/json; charset=utf-8",
		"content-length": Buffer.byteLength(payload),
		...extra,
	});
	res.end(payload);
}

export class HttpError extends Error {
	/** @param {number} status @param {string} message */
	constructor(status, message) {
		super(message);
		this.status = status;
	}
}

/** @param {import('node:http').IncomingMessage} req @returns {Promise<import('./types.mjs').Body>} */
export function readJson(req) {
	return new Promise((resolve, reject) => {
		const declared = Number(req.headers["content-length"]);
		if (declared > MAX_BODY) {
			req.resume();
			return reject(new HttpError(413, "body too large"));
		}
		/** @type {Buffer[]} */
		const chunks = [];
		let size = 0;
		let over = false;
		req.on("data", (c) => {
			if (over) return;
			size += c.length;
			if (size > MAX_BODY) {
				over = true;
				chunks.length = 0;
				reject(new HttpError(413, "body too large"));
				return;
			}
			chunks.push(c);
		});
		req.on("end", () => {
			if (over) return;
			try {
				const v = JSON.parse(Buffer.concat(chunks).toString("utf8") || "null");
				if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("not an object");
				resolve(v);
			} catch {
				reject(new HttpError(400, "invalid JSON"));
			}
		});
		req.on("error", reject);
	});
}

