// The version a nightly build of HEAD publishes as: package.json's version with a prerelease of
// the UTC time and the commit, e.g. 0.5.3-nightly.202611110643.g1a2b3c4. Nightlies of one version
// sort by time, and the g keeps a commit made of digits from reading as a number. The version in
// package.json is the prefix as it stands: nothing here, and nothing in nightly.yml, bumps it.
//
//   node scripts/nightly-version.mjs            the version
//   node scripts/nightly-version.mjs --commit   only the g<commit> part
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const commit = `g${execFileSync("git", ["rev-parse", "--short=7", "HEAD"], { encoding: "utf8" }).trim()}`;
if (process.argv.includes("--commit")) {
	console.log(commit);
	process.exit(0);
}
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const at = new Date().toISOString().replace(/\D/g, "").slice(0, 12);
console.log(`${version.split("-")[0]}-nightly.${at}.${commit}`);
