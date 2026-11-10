import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** `<platform>-<arch>` as Node names them: the directory a prebuilt binary lives in. */
export const platformKey = `${os.platform()}-${os.arch()}`;

const exe = os.platform() === "win32" ? "holywisp.exe" : "holywisp";

/** Where the binary for this platform is inside the installed package. */
export const bundledBinary = path.join(root, "bin", platformKey, exe);

