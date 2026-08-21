import { deepStrictEqual, rejects, strictEqual } from "node:assert/strict";
import { test } from "node:test";
import { SSHAesCtrHmacSha256, SSHCipherError } from "../cipher.ts";

function options() {
  return {
    encryptionKey: Uint8Array.from({ length: 16 }, (_, index) => index),
    initialCounter: Uint8Array.from({ length: 16 }, (_, index) => 16 + index),
    integrityKey: Uint8Array.from({ length: 32 }, (_, index) => 32 + index),
  };
}

test("AES-CTR HMAC-SHA256 protects sequential SSH packets", async () => {
  const sender = await SSHAesCtrHmacSha256.create(options());
  const receiver = await SSHAesCtrHmacSha256.create(options());
  const first = await sender.encrypt(Uint8Array.of(20, 1));
  const second = await sender.encrypt(Uint8Array.of(21, 2, 3));
  const combined = new Uint8Array(first.length + second.length);
  combined.set(first);
  combined.set(second, first.length);

  strictEqual(await receiver.read(combined.slice(0, 15)), undefined);
  const decodedFirst = await receiver.read(combined);
  if (!decodedFirst)
    throw new Error("expected first protected packet");
  deepStrictEqual(decodedFirst.payload, Uint8Array.of(20, 1));
  const decodedSecond = await receiver.read(combined.slice(decodedFirst.consumed));
  if (!decodedSecond)
    throw new Error("expected second protected packet");
  deepStrictEqual(decodedSecond.payload, Uint8Array.of(21, 2, 3));
});

test("AES-CTR HMAC-SHA256 rejects unauthenticated packets", async () => {
  const sender = await SSHAesCtrHmacSha256.create(options());
  const receiver = await SSHAesCtrHmacSha256.create(options());
  const packet = await sender.encrypt(Uint8Array.of(20));
  packet[packet.length - 1] ^= 1;
  await rejects(() => receiver.read(packet), SSHCipherError);
});
