// A harmless CLI fixture, not a Redis client. Records arguments and never opens a socket.
import { appendFileSync } from "node:fs";
if (!process.env.PI_SAFETY_E2E_LAUNCHES || !process.env.PI_SAFETY_E2E_ROOT) {
  throw new Error("Fake redis-cli requires isolated harness");
}
appendFileSync(process.env.PI_SAFETY_E2E_LAUNCHES, JSON.stringify({ cli: "redis-cli", args: process.argv.slice(2) }) + "\n");
console.log("fake redis-cli: no database contacted");
