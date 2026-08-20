import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { fingerprintSHA256, formatAuthorizedKey, parseAuthorizedKey, parsePublicKey, SSHKeyError } from "../keys.ts";
import { SSHWriter } from "../primitives.ts";

function ed25519Wire(): Uint8Array {
  return new SSHWriter()
    .writeString(new TextEncoder().encode("ssh-ed25519"))
    .writeString(Uint8Array.from({ length: 32 }, (_, index) => index))
    .toUint8Array();
}

test("SSH public keys preserve their wire representation", () => {
  const wire = ed25519Wire();
  const key = parsePublicKey(wire);

  strictEqual(key.type, "ssh-ed25519");
  deepStrictEqual(key.marshal(), wire);

  wire[0] = 255;
  deepStrictEqual(key.marshal(), ed25519Wire());
});

test("authorized-key text roundtrips canonically", () => {
  const key = parsePublicKey(ed25519Wire());
  const line = formatAuthorizedKey(key, "person@example.test");
  const parsed = parseAuthorizedKey(line.slice(0, -1));

  strictEqual(parsed.key.type, "ssh-ed25519");
  deepStrictEqual(parsed.key.marshal(), key.marshal());
  strictEqual(parsed.comment, "person@example.test");
  strictEqual(formatAuthorizedKey(parsed.key, parsed.comment), line);
});

test("authorized-key parsing rejects ambiguous and malformed input", () => {
  const line = formatAuthorizedKey(parsePublicKey(ed25519Wire())).slice(0, -1);
  throws(() => parseAuthorizedKey(`${line}\n`), SSHKeyError);
  throws(() => parseAuthorizedKey("ssh-ed25519 AAAA= comment"), SSHKeyError);
  throws(() => parseAuthorizedKey("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIA=="), SSHKeyError);
  throws(() => formatAuthorizedKey(parsePublicKey(ed25519Wire()), "line\nbreak"), SSHKeyError);
});

test("SSH SHA-256 fingerprints use the canonical unpadded OpenSSH form", async () => {
  const fingerprint = await fingerprintSHA256(parsePublicKey(ed25519Wire()));
  strictEqual(fingerprint, "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA");
});
