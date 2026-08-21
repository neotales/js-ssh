import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { formatPacket, readPacket, SSHPacketError } from "./packet.ts";

test("SSH packets roundtrip with RFC 4253 padding and preserve trailing bytes", () => {
  const payload = Uint8Array.of(20, 1, 2);
  const packet = formatPacket(payload, { padding: Uint8Array.from({ length: 8 }, (_, index) => index) });
  strictEqual(packet.length % 8, 0);
  const input = new Uint8Array(packet.length + 2);
  input.set(packet);
  input.set([9, 10], packet.length);
  const result = readPacket(input);
  if (!result)
    throw new Error("expected complete SSH packet");
  deepStrictEqual(result.payload, payload);
  strictEqual(result.consumed, packet.length);
});

test("SSH packet reader waits for complete packets and validates hostile framing", () => {
  const packet = formatPacket(Uint8Array.of(21));
  strictEqual(readPacket(packet.slice(0, -1)), undefined);
  throws(() => formatPacket(Uint8Array.of(1), { padding: Uint8Array.of(1, 2, 3, 4) }), SSHPacketError);
  throws(() => readPacket(packet, { maximumPacketLength: 5 }), SSHPacketError);

  const invalidPadding = packet.slice();
  invalidPadding[4] = 3;
  throws(() => readPacket(invalidPadding), SSHPacketError);
});
