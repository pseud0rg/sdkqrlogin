import { Pseud0WebLoginError } from "./types.js";

class Parser {
  private index = 0;
  public constructor(private readonly text: string) {}

  public parse(): unknown {
    const value = this.value();
    this.ws();
    if (this.index !== this.text.length) this.fail();
    return value;
  }

  private value(): unknown {
    this.ws();
    const c = this.text[this.index];
    if (c === "{") return this.object();
    if (c === "[") return this.array();
    if (c === '"') return this.string();
    if (c === "t" && this.take("true")) return true;
    if (c === "f" && this.take("false")) return false;
    if (c === "n" && this.take("null")) return null;
    return this.number();
  }

  private object(): Record<string, unknown> {
    this.index++;
    const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    const keys = new Set<string>();
    this.ws();
    if (this.text[this.index] === "}") {
      this.index++;
      return result;
    }
    for (;;) {
      this.ws();
      if (this.text[this.index] !== '"') this.fail();
      const key = this.string();
      if (keys.has(key)) this.fail();
      keys.add(key);
      this.ws();
      if (this.text[this.index++] !== ":") this.fail();
      result[key] = this.value();
      this.ws();
      const c = this.text[this.index++];
      if (c === "}") return result;
      if (c !== ",") this.fail();
    }
  }

  private array(): unknown[] {
    this.index++;
    const result: unknown[] = [];
    this.ws();
    if (this.text[this.index] === "]") {
      this.index++;
      return result;
    }
    for (;;) {
      result.push(this.value());
      this.ws();
      const c = this.text[this.index++];
      if (c === "]") return result;
      if (c !== ",") this.fail();
    }
  }

  private string(): string {
    const start = this.index++;
    let escaped = false;
    for (; this.index < this.text.length; this.index++) {
      const code = this.text.charCodeAt(this.index);
      if (code < 0x20) this.fail();
      if (!escaped && code === 0x22) {
        this.index++;
        try {
          return JSON.parse(this.text.slice(start, this.index)) as string;
        } catch {
          this.fail();
        }
      }
      if (!escaped && code === 0x5c) escaped = true;
      else escaped = false;
    }
    this.fail();
  }

  private number(): number {
    const remaining = this.text.slice(this.index);
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(remaining);
    if (!match) this.fail();
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) this.fail();
    return value;
  }

  private take(token: string): boolean {
    if (!this.text.startsWith(token, this.index)) return false;
    this.index += token.length;
    return true;
  }

  private ws(): void {
    while (" \t\r\n".includes(this.text[this.index] ?? "\0")) this.index++;
  }

  private fail(): never {
    throw new Pseud0WebLoginError("invalid_request");
  }
}

export function parseStrictJson(bytes: Uint8Array, maxBytes = 16_384): unknown {
  if (bytes.byteLength > maxBytes) throw new Pseud0WebLoginError("invalid_request");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Pseud0WebLoginError("invalid_request");
  }
  return new Parser(text).parse();
}

export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Pseud0WebLoginError("invalid_request");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`)
      .join(",")}}`;
  }
  throw new Pseud0WebLoginError("invalid_request");
}

export function assertExactKeys(
  value: unknown,
  keys: readonly string[],
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) {
    throw new Pseud0WebLoginError("invalid_request");
  }
}
