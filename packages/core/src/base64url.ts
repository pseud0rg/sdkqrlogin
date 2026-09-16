import { invalidRequest } from "./errors.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE64URL = /^[A-Za-z0-9_-]*$/;

export function encodeBase64Url(bytes: Uint8Array): string {
  let result = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1] ?? 0;
    const third = bytes[index + 2] ?? 0;
    const value = (first << 16) | (second << 8) | third;
    result += ALPHABET[(value >>> 18) & 63];
    result += ALPHABET[(value >>> 12) & 63];
    if (index + 1 < bytes.length) result += ALPHABET[(value >>> 6) & 63];
    if (index + 2 < bytes.length) result += ALPHABET[value & 63];
  }
  return result;
}

export function decodeBase64Url(value: string, expectedBytes?: number): Uint8Array {
  if (typeof value !== "string" || !BASE64URL.test(value) || value.length % 4 === 1) {
    invalidRequest();
  }

  const output = new Uint8Array(Math.floor((value.length * 6) / 8));
  let outputIndex = 0;
  let accumulator = 0;
  let bits = 0;
  for (const character of value) {
    const digit = ALPHABET.indexOf(character);
    if (digit < 0) invalidRequest();
    accumulator = accumulator * 64 + digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output[outputIndex++] = (accumulator >>> bits) & 0xff;
      accumulator &= (1 << bits) - 1;
    }
  }

  if (
    outputIndex !== output.length ||
    encodeBase64Url(output) !== value ||
    (expectedBytes !== undefined && output.length !== expectedBytes)
  ) {
    invalidRequest();
  }
  return output;
}

export function isCanonicalBase64Url(value: unknown, expectedBytes?: number): value is string {
  if (typeof value !== "string") return false;
  try {
    decodeBase64Url(value, expectedBytes);
    return true;
  } catch {
    return false;
  }
}
