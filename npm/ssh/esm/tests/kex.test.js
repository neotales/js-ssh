import { deepStrictEqual, rejects, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { deriveX25519Secret, formatKexEcdhInit, formatKexEcdhReply, formatKexInit, formatNewKeys, generateX25519KeyPair, isKexGuessCorrect, negotiateKexInit, parseKexEcdhInit, parseKexEcdhReply, parseKexInit, parseNewKeys, SSHKexError, } from "../kex.js";
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
test("SSH_MSG_KEXINIT negotiation follows client preference and detects incorrect guesses", () => {
    const client = {
        ...kexInit(),
        kexAlgorithms: ["curve25519-sha256", "diffie-hellman-group14-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519", "rsa-sha2-512"],
    };
    const server = {
        ...kexInit(),
        kexAlgorithms: ["diffie-hellman-group14-sha256", "curve25519-sha256"],
        serverHostKeyAlgorithms: ["rsa-sha2-512", "ssh-ed25519"],
        languagesClientToServer: ["en-US"],
    };
    const selection = negotiateKexInit(client, server);
    deepStrictEqual(selection, {
        kexAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "chacha20-poly1305@openssh.com",
        encryptionAlgorithmServerToClient: "chacha20-poly1305@openssh.com",
        macAlgorithmClientToServer: "none",
        macAlgorithmServerToClient: "none",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: undefined,
        languageServerToClient: undefined,
    });
    if (!isKexGuessCorrect(client, selection))
        throw new Error("expected client guess to be correct");
    if (isKexGuessCorrect({ ...server, kexAlgorithms: ["diffie-hellman-group14-sha256"] }, selection))
        throw new Error("expected server guess to be incorrect");
    throws(() => negotiateKexInit({ ...client, kexAlgorithms: ["none"] }, server), SSHKexError);
});
test("ECDH key-exchange messages preserve public keys, signatures, and NEWKEYS framing", () => {
    const clientPublic = Uint8Array.of(1, 2, 3);
    deepStrictEqual(parseKexEcdhInit(formatKexEcdhInit(clientPublic)), clientPublic);
    const reply = { hostKey: Uint8Array.of(4), serverPublic: Uint8Array.of(5, 6), signature: Uint8Array.of(7, 8, 9) };
    deepStrictEqual(parseKexEcdhReply(formatKexEcdhReply(reply)), reply);
    parseNewKeys(formatNewKeys());
    throws(() => formatKexEcdhInit(new Uint8Array()), SSHKexError);
    throws(() => parseNewKeys(Uint8Array.of(21, 0)));
});
test("X25519 peers derive the same 32-byte shared secret", async () => {
    const client = await generateX25519KeyPair();
    const server = await generateX25519KeyPair();
    strictEqual(client.publicKey.length, 32);
    strictEqual(server.publicKey.length, 32);
    deepStrictEqual(await deriveX25519Secret(client.privateKey, server.publicKey), await deriveX25519Secret(server.privateKey, client.publicKey));
    await rejects(() => deriveX25519Secret(client.privateKey, new Uint8Array(31)), SSHKexError);
});
