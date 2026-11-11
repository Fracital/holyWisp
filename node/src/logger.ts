import type { LogLevel } from "./config.js";

const priority: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3, none: 4 };

// Bold plus one of the eight base colours: every terminal that does colour at all does these.
const colours: Record<Exclude<LogLevel, "none">, string> = {
	debug: "\x1b[1;34m",
	info: "\x1b[1;35m",
	warn: "\x1b[1;33m",
	error: "\x1b[1;31m",
};

function useColour(): boolean {
	if (process.env["NO_COLOR"]) return false;
	if (process.env["FORCE_COLOR"] && process.env["FORCE_COLOR"] !== "0") return true;
	return Boolean(process.stdout.isTTY);
}

// 2026-11-09T22:41:07.123Z [warn] tag: message   (src/common/log.c)
const serverLine = /^\S+ \[(debug|info|warn|error)\] (.*)$/;

export class Logger {
	private readonly colour = useColour();

	constructor(public level: LogLevel = "warn") {}

	log(level: Exclude<LogLevel, "none">, message: string): void {
		if (priority[level] < priority[this.level]) return;
		const line = `[holyWisp]: ${message}`;
		console.log(this.colour ? `${colours[level]}${line}\x1b[0m` : line);
	}

	debug(message: string): void {
		this.log("debug", message);
	}
	info(message: string): void {
		this.log("info", message);
	}
	warn(message: string): void {
		this.log("warn", message);
	}
	error(message: string): void {
		this.log("error", message);
	}

	/**
	 * A line the server wrote to stderr. Its own level decides how it is shown (the server has
	 * already filtered by `logLevel`); a line that is not a log line is something going wrong
	 * before logging was up, or a crash, and is an error. `clean` is applied to what is shown (the
	 * wrapper's redaction of secrets), after the level has been read from the line as it came.
	 */
	server(line: string, clean: (text: string) => string = (text) => text): void {
		const match = serverLine.exec(line);
		if (match) this.log(match[1] as Exclude<LogLevel, "none">, clean(match[2] as string));
		else if (line.trim()) this.log("error", clean(line));
	}
}
