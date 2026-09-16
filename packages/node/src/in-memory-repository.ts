import { equalBytes } from "./crypto.js";
import {
  Pseud0WebLoginError,
  type WebLoginRepository,
  type WebLoginRequestRecord,
} from "./types.js";

const key = (value: Uint8Array): string => Buffer.from(value).toString("hex");
const copy = (value: Uint8Array): Uint8Array => Uint8Array.from(value);

function clone(record: WebLoginRequestRecord): WebLoginRequestRecord {
  return {
    ...record,
    sessionLookup: copy(record.sessionLookup),
    encryptedSession: copy(record.encryptedSession),
    browserSecretHash: copy(record.browserSecretHash),
    nonceLookup: copy(record.nonceLookup),
    encryptedNonce: copy(record.encryptedNonce),
    ...(record.encryptedSubject ? { encryptedSubject: copy(record.encryptedSubject) } : {}),
    ...(record.encryptedDisplayName
      ? { encryptedDisplayName: copy(record.encryptedDisplayName) }
      : {}),
    ...(record.relayJtiLookup ? { relayJtiLookup: copy(record.relayJtiLookup) } : {}),
    ...(record.assertionHash ? { assertionHash: copy(record.assertionHash) } : {}),
  };
}

export function createInMemoryWebLoginRepository(options: { testsOnly: true }): WebLoginRepository {
  if (options.testsOnly !== true || process.env.NODE_ENV === "production") {
    throw new Error("The in-memory web-login repository is tests-only");
  }
  const records = new Map<string, WebLoginRequestRecord>();
  const nonces = new Set<string>();
  const assertionReplays = new Map<string, Uint8Array>();
  const revocationReplays = new Map<string, Uint8Array>();

  return {
    async createRegistering(record) {
      const sessionKey = key(record.sessionLookup);
      const nonceKey = key(record.nonceLookup);
      if (records.has(sessionKey) || nonces.has(nonceKey)) {
        throw new Pseud0WebLoginError("invalid_request");
      }
      records.set(sessionKey, clone(record));
      nonces.add(nonceKey);
    },
    async markRegistered(sessionLookup, expectedVersion) {
      const record = records.get(key(sessionLookup));
      if (!record || record.state !== "registering" || record.version !== expectedVersion)
        return false;
      record.state = "registered";
      record.version++;
      return true;
    },
    async findForUpdate(sessionLookup) {
      const record = records.get(key(sessionLookup));
      return record ? clone(record) : null;
    },
    async acceptAssertion(input) {
      const replayKey = key(input.relayJtiLookup);
      const previous = assertionReplays.get(replayKey);
      if (previous) return equalBytes(previous, input.assertionHash) ? "same_retry" : "replay";
      const record = records.get(key(input.sessionLookup));
      if (
        !record ||
        record.state !== "registered" ||
        record.expiresAt < input.now ||
        !equalBytes(record.nonceLookup, input.nonceLookup)
      ) {
        return "replay";
      }
      assertionReplays.set(replayKey, copy(input.assertionHash));
      record.state = "assertion_received";
      record.encryptedSubject = copy(input.encryptedSubject);
      record.encryptedDisplayName = copy(input.encryptedDisplayName);
      record.relayJtiLookup = copy(input.relayJtiLookup);
      record.assertionHash = copy(input.assertionHash);
      record.version++;
      return "accepted";
    },
    async consume(input) {
      const record = records.get(key(input.sessionLookup));
      if (!record) return "invalid_state";
      if (record.state === "consumed") return "already_used";
      if (record.state !== "assertion_received" || record.version !== input.expectedVersion) {
        return "invalid_state";
      }
      record.state = "consumed";
      record.version++;
      return "consumed";
    },
    async cancel(sessionLookup, expectedVersion) {
      const record = records.get(key(sessionLookup));
      if (
        !record ||
        record.version !== expectedVersion ||
        ["consumed", "denied", "expired", "cancelled"].includes(record.state)
      ) {
        return false;
      }
      record.state = "cancelled";
      record.version++;
      return true;
    },
    async acceptRevocation(input) {
      const replayKey = key(input.relayJtiLookup);
      const previous = revocationReplays.get(replayKey);
      if (previous) return equalBytes(previous, input.payloadHash) ? "same_retry" : "replay";
      revocationReplays.set(replayKey, copy(input.payloadHash));
      return "accepted";
    },
    async expireBefore(now) {
      let count = 0;
      for (const record of records.values()) {
        if (
          record.expiresAt < now &&
          !["consumed", "denied", "expired", "cancelled"].includes(record.state)
        ) {
          record.state = "expired";
          record.version++;
          count++;
        }
      }
      return count;
    },
  };
}
