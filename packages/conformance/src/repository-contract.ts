import type {
  AcceptAssertionTransaction,
  WebLoginRepository,
  WebLoginRequestRecord,
} from "@pseud0/web-login-node";
import { describe, expect, it } from "vitest";

const bytes = (value: number, length = 32): Uint8Array => new Uint8Array(length).fill(value);

function record(id: number, expiresAt = 1_800_000_300_000): WebLoginRequestRecord {
  return {
    sessionLookup: bytes(id),
    encryptedSession: bytes(id + 1, 48),
    browserSecretHash: bytes(id + 2),
    nonceLookup: bytes(id + 3),
    encryptedNonce: bytes(id + 4, 48),
    state: "registering",
    issuedAt: 1_800_000_000_000,
    expiresAt,
    version: 0,
  };
}

async function registered(
  repository: WebLoginRepository,
  id: number,
  expiresAt?: number,
): Promise<WebLoginRequestRecord> {
  const value = record(id, expiresAt);
  await repository.createRegistering(value);
  expect(await repository.markRegistered(value.sessionLookup, 0)).toBe(true);
  return value;
}

function assertion(
  value: WebLoginRequestRecord,
  jti: number,
  hash: number,
  now = 1_800_000_100_000,
): AcceptAssertionTransaction {
  return {
    sessionLookup: value.sessionLookup,
    nonceLookup: value.nonceLookup,
    relayJtiLookup: bytes(jti),
    assertionHash: bytes(hash),
    encryptedSubject: bytes(90, 48),
    encryptedDisplayName: bytes(91, 48),
    expiresAt: value.expiresAt,
    now,
  };
}

/**
 * Registers the normative persistence tests in the current Vitest suite.
 * Factories must return a fresh, isolated repository for every invocation.
 */
export function defineWebLoginRepositoryContract(
  createRepository: () => Promise<WebLoginRepository>,
): void {
  describe("WebLoginRepository contract", () => {
    it("performs registration transitions with compare-and-set semantics", async () => {
      const repository = await createRepository();
      const value = record(10);
      await repository.createRegistering(value);

      expect(await repository.markRegistered(value.sessionLookup, 1)).toBe(false);
      expect((await repository.findForUpdate(value.sessionLookup))?.state).toBe("registering");
      expect(await repository.markRegistered(value.sessionLookup, 0)).toBe(true);
      expect(await repository.markRegistered(value.sessionLookup, 0)).toBe(false);
      expect(await repository.findForUpdate(value.sessionLookup)).toMatchObject({
        state: "registered",
        version: 1,
      });
    });

    it("rejects duplicate sessions and nonces", async () => {
      const repository = await createRepository();
      const first = record(20);
      await repository.createRegistering(first);

      await expect(
        repository.createRegistering({ ...record(21), sessionLookup: first.sessionLookup }),
      ).rejects.toBeDefined();
      await expect(
        repository.createRegistering({ ...record(22), nonceLookup: first.nonceLookup }),
      ).rejects.toBeDefined();
    });

    it("distinguishes an identical retry from a replay", async () => {
      const repository = await createRepository();
      const value = await registered(repository, 30);
      const first = assertion(value, 40, 41);

      await expect(repository.acceptAssertion(first)).resolves.toBe("accepted");
      await expect(repository.acceptAssertion(first)).resolves.toBe("same_retry");
      await expect(
        repository.acceptAssertion({ ...first, assertionHash: bytes(42) }),
      ).resolves.toBe("replay");
    });

    it("atomically accepts only one competing assertion", async () => {
      const repository = await createRepository();
      const value = await registered(repository, 50);
      const results = await Promise.all([
        repository.acceptAssertion(assertion(value, 51, 61)),
        repository.acceptAssertion(assertion(value, 52, 62)),
      ]);

      expect(results.filter((result) => result === "accepted")).toHaveLength(1);
      expect(results.filter((result) => result === "replay")).toHaveLength(1);
    });

    it("consumes a ready request exactly once using its version", async () => {
      const repository = await createRepository();
      const value = await registered(repository, 60);
      expect(await repository.acceptAssertion(assertion(value, 61, 62))).toBe("accepted");
      const ready = await repository.findForUpdate(value.sessionLookup);
      expect(ready).toMatchObject({ state: "assertion_received", version: 2 });

      expect(
        await repository.consume({
          sessionLookup: value.sessionLookup,
          expectedVersion: ready!.version - 1,
        }),
      ).toBe("invalid_state");
      expect(
        await repository.consume({
          sessionLookup: value.sessionLookup,
          expectedVersion: ready!.version,
        }),
      ).toBe("consumed");
      expect(
        await repository.consume({
          sessionLookup: value.sessionLookup,
          expectedVersion: ready!.version,
        }),
      ).toBe("already_used");
    });

    it("expires only active records strictly after their expiry", async () => {
      const repository = await createRepository();
      const expiry = 1_800_000_300_000;
      const active = await registered(repository, 70, expiry);

      expect(await repository.expireBefore(expiry)).toBe(0);
      expect(await repository.expireBefore(expiry + 1)).toBe(1);
      expect(await repository.expireBefore(expiry + 2)).toBe(0);
      expect(await repository.findForUpdate(active.sessionLookup)).toMatchObject({
        state: "expired",
        version: 2,
      });
      expect(await repository.acceptAssertion(assertion(active, 71, 72, expiry + 1))).toBe(
        "replay",
      );
    });

    it("applies cancellation with compare-and-set and preserves terminal state", async () => {
      const repository = await createRepository();
      const value = await registered(repository, 80);

      expect(await repository.cancel(value.sessionLookup, 0)).toBe(false);
      expect(await repository.cancel(value.sessionLookup, 1)).toBe(true);
      expect(await repository.cancel(value.sessionLookup, 1)).toBe(false);
      expect(await repository.findForUpdate(value.sessionLookup)).toMatchObject({
        state: "cancelled",
        version: 2,
      });
    });

    it("reserves revocation replay identifiers when supported", async () => {
      const repository = await createRepository();
      if (!repository.acceptRevocation) return;
      const input = {
        relayJtiLookup: bytes(90),
        subjectLookup: bytes(91),
        payloadHash: bytes(92),
        retainUntil: 1_800_000_300_000,
      };

      await expect(repository.acceptRevocation(input)).resolves.toBe("accepted");
      await expect(repository.acceptRevocation(input)).resolves.toBe("same_retry");
      await expect(repository.acceptRevocation({ ...input, payloadHash: bytes(93) })).resolves.toBe(
        "replay",
      );
    });
  });
}
