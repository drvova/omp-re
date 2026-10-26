/**
 * How values read in a `run` result, shared by the namespace worker (which
 * formats what a cell prints and returns) and the host side (errors).
 */
import { formatJson } from "./format.ts";

/** `Name: message` for anything thrown, including errors from another realm (where `instanceof Error` is false). */
export function errorText(err: unknown): string {
	if (err && typeof err === "object" && "message" in err) {
		const name = (err as { name?: unknown }).name;
		const message = String((err as { message: unknown }).message);
		return typeof name === "string" && name !== "Error" && !message.startsWith(`${name}:`) ? `${name}: ${message}` : message;
	}
	return String(err);
}

/** A value as plain JSON-able data: Map/Set/bigint/functions/cycles made printable. */
function toPlain(value: unknown, seen: WeakSet<object>): unknown {
	if (typeof value === "bigint") return `${value}n`;
	if (typeof value === "function") return `[function ${value.name || "anonymous"}]`;
	if (typeof value === "symbol") return value.toString();
	if (value === undefined) return null;
	if (value === null || typeof value !== "object") return value;
	if (seen.has(value)) return "[circular]";
	seen.add(value);
	try {
		if (typeof (value as { then?: unknown }).then === "function") return "[Promise — await it]";
		const tag = Object.prototype.toString.call(value);
		if (tag === "[object Map]") return Object.fromEntries([...(value as Map<unknown, unknown>)].map(([k, v]) => [String(k), toPlain(v, seen)]));
		if (tag === "[object Set]") return [...(value as Set<unknown>)].map((v) => toPlain(v, seen));
		if (tag === "[object Error]") return errorText(value);
		if (Array.isArray(value)) return value.map((v) => toPlain(v, seen));
		if (ArrayBuffer.isView(value)) return Array.from(value as unknown as ArrayLike<number>);
		const out: Record<string, unknown> = {};
		for (const key of Object.keys(value)) out[key] = toPlain((value as Record<string, unknown>)[key], seen);
		return out;
	} finally {
		seen.delete(value);
	}
}

/** How a printed argument or the call's value reads in the result: strings verbatim, everything else as JSON (arrays one row per line). */
export function show(value: unknown): string {
	if (typeof value === "string") return value;
	if (value === undefined) return "undefined";
	const plain = toPlain(value, new WeakSet());
	return typeof plain === "string" ? plain : formatJson(plain);
}
