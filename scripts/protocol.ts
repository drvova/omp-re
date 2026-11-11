/**
 * stdio/protocol.json as TypeScript reads it: the description of the wire
 * between omp and the engine, and the check of a value against one of its
 * types. The generator (gen-protocol.ts) and the bun suites' stand-in engine
 * use this; the Lisp side reads the same file with stdio/protocol.lisp, which
 * also says what a type is.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

export type Type = string | { enum: string[] } | { array: Type } | { tuple: Type[] } | { map: Type } | { oneOf: Type[] } | { members: Members };
export type Members = Record<string, Type>;

export interface Method {
	kind: "request" | "notification";
	/** Done in the order it arrives, before anything after it on the pipe. */
	ordered?: boolean;
	params: Members;
	result?: Type;
}

export type Direction = "toEngine" | "toHost";

export interface Protocol {
	version: number;
	constants: Record<string, string | number>;
	keys: { views: { key: string; view: string }[]; code: { key: string; action: string; short: string; long: string }[] };
	types: Record<string, Type>;
	toEngine: Record<string, Method>;
	toHost: Record<string, Method>;
}

export const PROTOCOL_FILE = join(import.meta.dir, "..", "stdio", "protocol.json");

export function readProtocol(): Protocol {
	return JSON.parse(readFileSync(PROTOCOL_FILE, "utf8")) as Protocol;
}

const optional = (name: string) => name.endsWith("?");
const bare = (name: string) => (optional(name) ? name.slice(0, -1) : name);

function shown(value: unknown): string {
	const text = JSON.stringify(value) ?? String(value);
	return text.length > 80 ? `${text.slice(0, 80)}…` : text;
}

/** Why `value`, found at `where`, is not of `type`; undefined when it is. */
export function violation(protocol: Protocol, type: Type, value: unknown, where: string): string | undefined {
	const need = (holds: boolean, expected: string) => (holds ? undefined : `${where} must be ${expected}, not ${shown(value)}`);
	const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
	if (typeof type === "string") {
		if (type.startsWith("@")) {
			const named = protocol.types[type.slice(1)];
			if (named === undefined) throw new Error(`the protocol has no type ${type}`);
			return violation(protocol, named, value, where);
		}
		switch (type) {
			case "string":
				return need(typeof value === "string", "a string");
			case "integer":
				return need(Number.isInteger(value), "an integer");
			case "number":
				return need(typeof value === "number", "a number");
			case "boolean":
				return need(typeof value === "boolean", "true or false");
			case "null":
				return need(value === null, "null");
			case "object":
				return need(isObject(value), "an object");
			case "json":
				return need(value !== undefined, "a JSON value");
			default:
				throw new Error(`the protocol names no type ${type}`);
		}
	}
	if ("enum" in type) return need(typeof value === "string" && type.enum.includes(value), `one of ${type.enum.join(", ")}`);
	if ("array" in type) {
		if (!Array.isArray(value)) return need(false, "an array");
		for (const [index, item] of value.entries()) {
			const wrong = violation(protocol, type.array, item, `${where}[${index}]`);
			if (wrong) return wrong;
		}
		return undefined;
	}
	if ("tuple" in type) {
		if (!Array.isArray(value) || value.length !== type.tuple.length) return need(false, `an array of ${type.tuple.length}`);
		for (const [index, item] of value.entries()) {
			const wrong = violation(protocol, type.tuple[index]!, item, `${where}[${index}]`);
			if (wrong) return wrong;
		}
		return undefined;
	}
	if ("map" in type) {
		if (!isObject(value)) return need(false, "an object");
		for (const [key, item] of Object.entries(value)) {
			const wrong = violation(protocol, type.map, item, `${where}.${key}`);
			if (wrong) return wrong;
		}
		return undefined;
	}
	if ("oneOf" in type) {
		const reasons = type.oneOf.map((one) => violation(protocol, one, value, where));
		if (reasons.some((reason) => reason === undefined)) return undefined;
		// The case that got furthest says the most.
		return (reasons as string[]).sort((a, b) => b.length - a.length)[0];
	}
	if (!isObject(value)) return need(false, "an object");
	for (const [spelled, memberType] of Object.entries(type.members)) {
		const name = bare(spelled);
		if (value[name] === undefined) {
			if (!optional(spelled)) return `${where} lacks ${name}`;
			continue;
		}
		const wrong = violation(protocol, memberType, value[name], `${where}.${name}`);
		if (wrong) return wrong;
	}
	const known = new Set(Object.keys(type.members).map(bare));
	for (const name of Object.keys(value)) if (value[name] !== undefined && !known.has(name)) return `${where} has no member ${name}`;
	return undefined;
}

/** Why a message is not one the protocol has for `direction`; undefined when it is. `request` says whether it carries an id. */
export function paramsViolation(protocol: Protocol, direction: Direction, method: string, params: unknown, request: boolean): string | undefined {
	const described = protocol[direction][method];
	if (!described) return `there is no ${direction === "toEngine" ? "engine" : "omp"} method ${shown(method)}`;
	if ((described.kind === "request") !== request) return `${method} is a ${described.kind}`;
	return violation(protocol, { members: described.params }, params, `${method}'s params`);
}

export function resultViolation(protocol: Protocol, direction: Direction, method: string, result: unknown): string | undefined {
	const described = protocol[direction][method];
	if (!described?.result) return `${method} has no result`;
	return violation(protocol, described.result, result, `${method}'s result`);
}
