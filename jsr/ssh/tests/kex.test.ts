import { deepStrictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { formatKexInit, parseKexInit, SSHKexError } from "../kex.ts";

function kexInit() {
  return {
    cookie: Uint8Array.from({ length: 16 }, (_, index) => index),
    kexAlgorithms: ["curve25519-sha256"],
    serverHostKeyAlgorithms: ["ssh-ed25519"],
    encryptionAlgorithmsClientToServer: ["chacha20-poly1305@openssh.com"],
    encryptionAlgorithmsServerToClient: ["chacha20-poly1305@openssh.com"],
    macAlgorithmsClientToServer: ["none"],
    macAlgorithmsServerToClient: ["none"],
    compressionAlgorithmsClientToServer: ["none"],
    compressionAlgorithmsServerToClient: ["none"],
    languagesClientToServer: [],
    languagesServerToClient: [],
    firstKexPacketFollows: false,
  };
}

test("SSH_MSG_KEXINIT roundtrips algorithm proposals", () => {
  const expected = kexInit();
  const parsed = parseKexInit(formatKexInit(expected));
  deepStrictEqual(parsed, expected);
});

test("SSH_MSG_KEXINIT rejects invalid message, cookie, reserved field, and mandatory lists", () => {
  throws(() => parseKexInit(Uint8Array.of(21)), SSHKexError);
  throws(() => formatKexInit({ ...kexInit(), cookie: new Uint8Array(15) }), SSHKexError);
  throws(() => formatKexInit({ ...kexInit(), kexAlgorithms: [] }), SSHKexError);

  const reserved = formatKexInit(kexInit());
  reserved[reserved.length - 1] = 1;
  throws(() => parseKexInit(reserved), SSHKexError);
});
