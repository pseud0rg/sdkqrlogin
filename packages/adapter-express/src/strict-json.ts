import { Pseud0WebLoginError } from "@pseud0/web-login-node";

class Parser {
  private index = 0;

  public constructor(private readonly text: string) {}

  public parse(): unknown {
    const value = this.value();
    this.whitespace();
    if (this.index !== this.text.length) this.fail();
    return value;
  }

  private value(): unknown {
    this.whitespace();
    const character = this.text[this.index];
    if (character === "{") return this.object();
    if (character === "[") return this.array();
    if (character === '"') return this.string();
    if (character === "t" && this.take("true")) return true;
    if (character === "f" && this.take("false")) return false;
    if (character === "n" && this.take("null")) return null;
    return this.number();
  }

  private object(): Record<string, unknown> {
    this.index++;
    const value: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    const keys = new Set<string>();
    this.whitespace();
    if (this.text[this.index] === "}") {
      this.index++;
      return value;
    }
    for (;;) {
      this.whitespace();
      if (this.text[this.index] !== '"') this.fail();
      const key = this.string();
      if (keys.has(key)) this.fail();
      keys.add(key);
      this.whitespace();
      if (this.text[this.index++] !== ":") this.fail();
      value[key] = this.value();
      this.whitespace();
      const separator = this.text[this.index++];
      if (separator === "}") return value;
      if (separator !== ",") this.fail();
    }
  }

  private array(): unknown[] {
    this.index++;
    const value: unknown[] = [];
    this.whitespace();
    if (this.text[this.index] === "]") {
      this.index++;
      return value;
    }
    for (;;) {
      value.push(this.value());
      this.whitespace();
      const separator = this.text[this.index++];
      if (separator === "]") return value;
      if (separator !== ",") this.fail();
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
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(this.text.slice(this.index));
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

  private whitespace(): void {
    while (" \t\r\n".includes(this.text[this.index] ?? "\0")) this.index++;
  }

  private fail(): never {
    throw new Pseud0WebLoginError("invalid_request");
  }
}

export function parseBrowserSecret(body: Uint8Array): string {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new Pseud0WebLoginError("invalid_request");
  }
  const value = new Parser(text).parse();
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 1 ||
    !Object.hasOwn(value, "browser_secret")
  ) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  const secret = (value as Record<string, unknown>).browser_secret;
  if (typeof secret !== "string" || !/^[A-Za-z0-9_-]{22,128}$/.test(secret)) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  return secret;
}
