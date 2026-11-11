// Build what `npm pack` ships: the compiled wrapper (dist/), one server binary per platform
// (bin/<platform>-<arch>/) and the licence.
//
//   node scripts/build.mjs                       every target below
//   node scripts/build.mjs --targets linux-x64   only these (comma-separated)
//   node scripts/build.mjs --no-binaries         dist/ only
//
// The binaries are cross-compiled from this tree with `zig cc` through the normal CMake build
// (cmake/zig-toolchain.cmake), so one machine produces all of them. ZIG names the executable;
// otherwise `zig`, then `python-zig` (what `pip install ziglang` provides), is used.
import { spawnSync } from "node:child_process";
import { chmodSync, closeSync, copyFileSync, mkdirSync, openSync, readFileSync, readSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Node's <platform>-<arch> to the zig target. Linux builds are static against musl: they run on
// any distribution, glibc or musl, with nothing installed. They are static PIEs with a stack
// protector (CMakeLists.txt, "Exploit mitigations"): the kernel loads them at a random address,
// and `isPie` below fails the build if a zig that stops making them so comes along. Two things
// musl does not give a static binary: checked variants of its functions (FORTIFY) and a
// read-only RELRO segment. macOS builds link libSystem, as everything there does, target macOS
// 13 (the oldest release a supported Node runs on), and zig signs them ad hoc (arm64 will not
// run unsigned code). Windows builds are MinGW ones: they need nothing but the DLLs Windows 10
// itself has. Adding a platform here is the last step of porting the server to it (a loop
// backend and a half of sys.h); the wrapper already looks in bin/<platform>-<arch>/.
const TARGETS = {
	"linux-x64": "x86_64-linux-musl",
	"linux-arm64": "aarch64-linux-musl",
	"darwin-x64": "x86_64-macos.13.0",
	"darwin-arm64": "aarch64-macos.13.0",
	"win32-x64": "x86_64-windows-gnu",
	"win32-arm64": "aarch64-windows-gnu",
};

const pkg = fileURLToPath(new URL("../", import.meta.url));
const repo = fileURLToPath(new URL("../../", import.meta.url));

// The binaries report the package's version. The server has its own number (CMakeLists.txt, held
// equal to package.json's by the wrapper's tests); what a prerelease adds to it, as a nightly's
// "-nightly.<time>.g<commit>" does, is handed to the C build as the suffix `--version` prints.
const { version } = JSON.parse(readFileSync(join(pkg, "package.json"), "utf8"));
const dash = version.indexOf("-");
const versionSuffix = dash < 0 ? "" : version.slice(dash);

function run(command, args, options = {}) {
	const result = spawnSync(command, args, { stdio: "inherit", ...options });
	if (result.error) throw result.error;
	if (result.status !== 0) process.exit(result.status ?? 1);
}

function works(command, args) {
	return spawnSync(command, args, { stdio: "ignore" }).status === 0;
}

// Is this ELF file position-independent (e_type ET_DYN, the u16 at offset 16)? A fixed-address
// executable is ET_EXEC. Both Linux targets are little-endian.
function isPie(file) {
	const head = Buffer.alloc(18);
	const fd = openSync(file, "r");
	try {
		readSync(fd, head, 0, head.length, 0);
	} finally {
		closeSync(fd);
	}
	return head.toString("latin1", 0, 4) === "\x7fELF" && head.readUInt16LE(16) === 3;
}

function findZig() {
	for (const candidate of process.env.ZIG ? [process.env.ZIG] : ["zig", "python-zig"]) {
		if (works(candidate, ["version"])) return candidate;
	}
	console.error("build: zig not found. Install it (https://ziglang.org, or `pip install ziglang`) or set ZIG.");
	process.exit(1);
}

const argv = process.argv.slice(2);
const only = argv.includes("--targets") ? argv[argv.indexOf("--targets") + 1]?.split(",") : undefined;
const targets = only ?? Object.keys(TARGETS);
for (const key of targets) {
	if (!TARGETS[key]) {
		console.error(`build: unknown target '${key}'. Known: ${Object.keys(TARGETS).join(", ")}`);
		process.exit(1);
	}
}

if (!argv.includes("--no-binaries")) {
	const zig = findZig();
	const generator = works("ninja", ["--version"]) ? ["-G", "Ninja"] : [];
	rmSync(join(pkg, "bin"), { recursive: true, force: true });
	for (const key of targets) {
		const tree = join(repo, "build", "npm", key);
		run("cmake", [
			"-S", repo,
			"-B", tree,
			...generator,
			"-DCMAKE_BUILD_TYPE=Release",
			"-DHW_BUILD_TESTS=OFF",
			`-DCMAKE_TOOLCHAIN_FILE=${join(repo, "cmake", "zig-toolchain.cmake")}`,
			`-DHW_ZIG=${zig}`,
			`-DHW_ZIG_TARGET=${TARGETS[key]}`,
			"-DCMAKE_EXE_LINKER_FLAGS=-s",
			// Always passed: an empty one clears what an earlier nightly build left in the cache.
			`-DHW_VERSION_SUFFIX=${versionSuffix}`,
		]);
		run("cmake", ["--build", tree, "--target", "holywisp-bin"]);
		const exe = key.startsWith("win32") ? "holywisp.exe" : "holywisp";
		if (key.startsWith("linux") && !isPie(join(tree, exe))) {
			console.error(`build: ${key}: ${exe} is not a position-independent executable (see CMakeLists.txt, HW_HARDEN)`);
			process.exit(1);
		}
		mkdirSync(join(pkg, "bin", key), { recursive: true });
		copyFileSync(join(tree, exe), join(pkg, "bin", key, exe));
		chmodSync(join(pkg, "bin", key, exe), 0o755);
	}
	console.log(`build: server binaries for ${targets.join(", ")}`);
}

rmSync(join(pkg, "dist"), { recursive: true, force: true });
run(process.execPath, [join(pkg, "node_modules", "typescript", "bin", "tsc"), "-p", pkg]);
copyFileSync(join(repo, "LICENSE"), join(pkg, "LICENSE"));
console.log("build: dist/ compiled");
