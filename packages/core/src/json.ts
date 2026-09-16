import { invalidRequest } from "./errors.js";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

class StrictJsonParser {
  private offset = 0;

  constructor(private readonly text: string) {}

  parse(): JsonValue {
    this.space();
    const value = this.value();
    this.space();
    if (this.offset !== this.text.length) invalidRequest();
    return value;
  }

  private value(): JsonValue {
    const character = this.text[this.offset];
    if (character === '"') return this.string();
    if (character === "{") return this.object();
    if (character === "[") return this.array();
    if (character === "t") return this.literal("true", true);
    if (character === "f") return this.literal("false", false);
    if (character === "n") return this.literal("null", null);
    return this.number();
  }

  private literal<T extends JsonPrimitive>(token: string, value: T): T {
    if (this.text.slice(this.offset, this.offset + token.length) !== token) {
      invalidRequest();
    }
    this.offset += token.length;
    return value;
  }

  private object(): { [key: string]: JsonValue } {
    this.offset++;
    this.space();
    const result: { [key: string]: JsonValue } = {};
    const keys = new Set<string>();
    if (this.text[this.offset] === "}") {
      this.offset++;
      return result;
    }
    while (true) {
      if (this.text[this.offset] !== '"') invalidRequest();
      const key = this.string();
      if (keys.has(key)) invalidRequest();
      keys.add(key);
      this.space();
      if (this.text[this.offset++] !== ":") invalidRequest();
      this.space();
      Object.defineProperty(result, key, {
        value: this.value(),
        enumerable: true,
        configurable: true,
        writable: true,
      });
      this.space();
      const separator = this.text[this.offset++];
      if (separator === "}") return result;
      if (separator !== ",") invalidRequest();
      this.space();
    }
  }

  private array(): JsonValue[] {
    this.offset++;
    this.space();
    const result: JsonValue[] = [];
    if (this.text[this.offset] === "]") {
      this.offset++;
      return result;
    }
    while (true) {
      result.push(this.value());
      this.space();
      const separator = this.text[this.offset++];
      if (separator === "]") return result;
      if (separator !== ",") invalidRequest();
      this.space();
    }
  }

  private string(): string {
    const start = this.offset;
    this.offset++;
    while (this.offset < this.text.length) {
      const character = this.text.charCodeAt(this.offset++);
      if (character === 0x22) {
        const token = this.text.slice(start, this.offset);
        try {
          const parsed: unknown = JSON.parse(token);
          if (typeof parsed !== "string" || hasLoneSurrogate(parsed)) {
            invalidRequest();
          }
          return parsed;
        } catch {
          invalidRequest();
        }
      }
      if (character < 0x20) invalidRequest();
      if (character === 0x5c) {
        const escape = this.text.charCodeAt(this.offset++);
        if (escape === 0x75) {
          if (!/^[0-9a-fA-F]{4}$/.test(this.text.slice(this.offset, this.offset + 4))) {
            invalidRequest();
          }
          this.offset += 4;
        } else if (![0x22, 0x5c, 0x2f, 0x62, 0x66, 0x6e, 0x72, 0x74].includes(escape)) {
          invalidRequest();
        }
      }
    }
    return invalidRequest();
  }

  private number(): number {
    const remainder = this.text.slice(this.offset);
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(remainder);
    if (match === null) invalidRequest();
    const token = match[0];
    this.offset += token.length;
    const value = Number(token);
    if (!Number.isFinite(value)) invalidRequest();
    return value;
  }

  private space(): void {
    while (
      this.text[this.offset] === " " ||
      this.text[this.offset] === "\t" ||
      this.text[this.offset] === "\n" ||
      this.text[this.offset] === "\r"
    ) {
      this.offset++;
    }
  }
}

export function parseJsonStrict(input: string | Uint8Array): JsonValue {
  let text: string;
  try {
    text = typeof input === "string" ? input : decoder.decode(input);
  } catch {
    return invalidRequest();
  }
  return new StrictJsonParser(text).parse();
}

export function canonicalizeJson(value: JsonValue): string {
  return canonical(value);
}

function canonical(value: JsonValue): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalidRequest();
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    if (hasLoneSurrogate(value)) invalidRequest();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonical(item)).join(",")}]`;
  }
  if (typeof value !== "object") return invalidRequest();
  const keys = Object.keys(value);
  for (const key of keys) {
    if (hasLoneSurrogate(key)) invalidRequest();
  }
  keys.sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key]!)}`).join(",")}}`;
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}
