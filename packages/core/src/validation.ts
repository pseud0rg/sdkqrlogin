import { isCanonicalBase64Url } from "./base64url.js";
import { invalidRequest } from "./errors.js";
import type { JsonValue } from "./json.js";

export const DOMAIN_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
export const OPAQUE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
export const OPAQUE_128_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
export const KID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

export type JsonObject = Record<string, JsonValue>;

export function objectWithExactKeys(value: JsonValue, keys: readonly string[]): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    invalidRequest();
  }
  const actual = Object.keys(value);
  if (
    actual.length !== keys.length ||
    keys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    invalidRequest();
  }
  return value;
}

export function stringValue(
  value: JsonValue | undefined,
  options: {
    min?: number;
    max?: number;
    pattern?: RegExp;
    nonBlank?: boolean;
  } = {},
): string {
  if (typeof value !== "string") invalidRequest();
  if (
    (options.min !== undefined && value.length < options.min) ||
    (options.max !== undefined && value.length > options.max) ||
    (options.pattern !== undefined && !options.pattern.test(value)) ||
    (options.nonBlank === true && value.trim().length === 0)
  ) {
    invalidRequest();
  }
  return value;
}

export function domainValue(value: JsonValue | undefined): string {
  return stringValue(value, { max: 253, pattern: DOMAIN_PATTERN });
}

export function integerValue(value: JsonValue | undefined, minimum?: number): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    (minimum !== undefined && value < minimum)
  ) {
    invalidRequest();
  }
  return value;
}

export function versionValue(value: JsonValue | undefined): 1 {
  if (value !== 1) invalidRequest();
  return 1;
}

export function signatureValue(value: JsonValue | undefined): string {
  const result = stringValue(value);
  if (!isCanonicalBase64Url(result, 64)) invalidRequest();
  return result;
}

export function publicKeyValue(value: JsonValue | undefined): string {
  const result = stringValue(value);
  if (!isCanonicalBase64Url(result, 32)) invalidRequest();
  return result;
}

export function opaqueValue(value: JsonValue | undefined, minimumCharacters = 16): string {
  return stringValue(value, {
    pattern: minimumCharacters === 22 ? OPAQUE_128_PATTERN : OPAQUE_PATTERN,
  });
}
