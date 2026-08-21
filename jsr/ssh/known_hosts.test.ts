import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { formatAuthorizedKey, parsePublicKey } from "./keys.ts";
import { hashKnownHost, matchesKnownHost, parseKnownHost, parseKnownHosts, verifyKnownHost } from "./known_hosts.ts";
import { SSHWriter } from "./primitives.ts";

function publicKeyLine(): string {
  const key = parsePublicKey(
    new SSHWriter()
      .writeString(new TextEncoder().encode("ssh-ed25519"))
      .writeString(Uint8Array.from({ length: 32 }, (_, index) => index))
      .toUint8Array(),
  );
  return formatAuthorizedKey(key, "host-key").slice(0, -1);
}

test("known_hosts parsing preserves markers, patterns, keys, and comments", () => {
  const entry = parseKnownHost(`@cert-authority example.test,*.internal ${publicKeyLine()}`);

  strictEqual(entry.marker, "@cert-authority");
  deepStrictEqual(entry.hosts, ["example.test", "*.internal"]);
  strictEqual(entry.key.type, "ssh-ed25519");
  strictEqual(entry.comment, "host-key");
});

test("known_hosts parsing skips blank and comment lines", () => {
  const entries = parseKnownHosts(`# comment\n\nexample.test ${publicKeyLine()}\n`);
  strictEqual(entries.length, 1);
  strictEqual(entries[0].key.type, "ssh-ed25519");
});

test("known_hosts matching supports exact, wildcard, negated, and hashed patterns", async () => {
  const entry = parseKnownHost(`example.test,*.internal,!blocked.internal ${publicKeyLine()}`);
  strictEqual(await matchesKnownHost(entry, "example.test"), true);
  strictEqual(await matchesKnownHost(entry, "api.internal"), true);
  strictEqual(await matchesKnownHost(entry, "blocked.internal"), false);
  strictEqual(await matchesKnownHost(entry, "other.test"), false);

  const hashed = await hashKnownHost("example.test", Uint8Array.of(1, 2, 3, 4));
  const hashedEntry = parseKnownHost(`${hashed} ${publicKeyLine()}`);
  strictEqual(await matchesKnownHost(hashedEntry, "example.test"), true);
  strictEqual(await matchesKnownHost(hashedEntry, "other.test"), false);
});

test("known_hosts parsing rejects unsupported markers and empty patterns", () => {
  throws(() => parseKnownHost(`@unknown example.test ${publicKeyLine()}`));
  throws(() => parseKnownHost(`example.test,,other.test ${publicKeyLine()}`));
});

test("known_hosts verification distinguishes trusted, changed, revoked, and unknown keys", async () => {
  const trusted = parseKnownHost(`example.test ${publicKeyLine()}`);
  const revoked = parseKnownHost(`@revoked example.test ${publicKeyLine()}`);
  const otherKey = parsePublicKey(
    new SSHWriter()
      .writeString(new TextEncoder().encode("ssh-ed25519"))
      .writeString(Uint8Array.from({ length: 32 }, (_, index) => 255 - index))
      .toUint8Array(),
  );

  strictEqual(await verifyKnownHost([trusted], "example.test", trusted.key), "trusted");
  strictEqual(await verifyKnownHost([trusted], "example.test", otherKey), "changed");
  strictEqual(await verifyKnownHost([trusted], "other.test", trusted.key), "unknown");
  strictEqual(await verifyKnownHost([trusted, revoked], "example.test", trusted.key), "revoked");
});
