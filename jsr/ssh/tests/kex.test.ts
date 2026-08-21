import { deepStrictEqual, notDeepStrictEqual, rejects, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import {
  computeCurve25519Sha256ExchangeHash,
  computeCurve25519Sha256ExchangeHashSync,
  deriveKeyMaterial,
  deriveKeyMaterialSync,
  deriveX25519Secret,
  deriveX25519SecretSync,
  formatKexEcdhInit,
  formatKexEcdhReply,
  formatKexInit,
  formatNewKeys,
  generateX25519KeyPair,
  generateX25519KeyPairSync,
  isKexGuessCorrect,
  isSyncKexSupported,
  negotiateKexInit,
  parseKexEcdhInit,
  parseKexEcdhReply,
  parseKexInit,
  parseNewKeys,
  SSHKexError,
  verifyCurve25519Sha256Reply,
} from "../kex.ts";
import { generateEd25519KeyPair, signEd25519 } from "../keys.ts";

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
  deepStrictEqual(
    await deriveX25519Secret(client.privateKey, server.publicKey),
    await deriveX25519Secret(server.privateKey, client.publicKey),
  );
  await rejects(() => deriveX25519Secret(client.privateKey, new Uint8Array(31)), SSHKexError);
});

test("curve25519-sha256 exchange hashes bind every negotiated transcript field", async () => {
  const input = {
    clientIdentification: "SSH-2.0-client",
    serverIdentification: "SSH-2.0-server",
    clientKexInit: Uint8Array.of(20, 1),
    serverKexInit: Uint8Array.of(20, 2),
    hostKey: Uint8Array.of(3),
    clientPublic: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    serverPublic: Uint8Array.from({ length: 32 }, (_, index) => index + 33),
    sharedSecret: Uint8Array.from({ length: 32 }, (_, index) => index + 65),
  };
  const hash = await computeCurve25519Sha256ExchangeHash(input);
  strictEqual(hash.length, 32);
  notDeepStrictEqual(
    hash,
    await computeCurve25519Sha256ExchangeHash({ ...input, serverKexInit: Uint8Array.of(20, 3) }),
  );
  await rejects(
    () => computeCurve25519Sha256ExchangeHash({ ...input, sharedSecret: new Uint8Array(32) }),
    SSHKexError,
  );
});

test("RFC 4253 key material expands deterministically and separates directional labels", async () => {
  const secret = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const exchangeHash = Uint8Array.from({ length: 32 }, (_, index) => index + 33);
  const first = await deriveKeyMaterial(secret, exchangeHash, exchangeHash, "A", 64);
  deepStrictEqual(first, await deriveKeyMaterial(secret, exchangeHash, exchangeHash, "A", 64));
  strictEqual(first.length, 64);
  notDeepStrictEqual(first, await deriveKeyMaterial(secret, exchangeHash, exchangeHash, "B", 64));
  await rejects(() => deriveKeyMaterial(new Uint8Array(32), exchangeHash, exchangeHash, "A", 1), SSHKexError);
});

test("synchronous KEX APIs use Node-compatible crypto without static imports", async () => {
  strictEqual(isSyncKexSupported(), true);
  const client = generateX25519KeyPairSync();
  const server = generateX25519KeyPairSync();
  const secret = deriveX25519SecretSync(client.privateKey, server.publicKey);
  deepStrictEqual(secret, deriveX25519SecretSync(server.privateKey, client.publicKey));
  const input = {
    clientIdentification: "SSH-2.0-client",
    serverIdentification: "SSH-2.0-server",
    clientKexInit: Uint8Array.of(20, 1),
    serverKexInit: Uint8Array.of(20, 2),
    hostKey: Uint8Array.of(3),
    clientPublic: client.publicKey,
    serverPublic: server.publicKey,
    sharedSecret: secret,
  };
  deepStrictEqual(computeCurve25519Sha256ExchangeHashSync(input), await computeCurve25519Sha256ExchangeHash(input));
  const hash = computeCurve25519Sha256ExchangeHashSync(input);
  deepStrictEqual(
    deriveKeyMaterialSync(secret, hash, hash, "C", 64),
    await deriveKeyMaterial(secret, hash, hash, "C", 64),
  );
});

test("curve25519-sha256 authenticates an Ed25519 server reply", async () => {
  const client = await generateX25519KeyPair();
  const server = await generateX25519KeyPair();
  const host = await generateEd25519KeyPair();
  const clientKexInit = formatKexInit(kexInit());
  const serverKexInit = formatKexInit(kexInit());
  const sharedSecret = await deriveX25519Secret(server.privateKey, client.publicKey);
  const exchangeHash = await computeCurve25519Sha256ExchangeHash({
    clientIdentification: "SSH-2.0-client",
    serverIdentification: "SSH-2.0-server",
    clientKexInit,
    serverKexInit,
    hostKey: host.publicKey.marshal(),
    clientPublic: client.publicKey,
    serverPublic: server.publicKey,
    sharedSecret,
  });
  const signature = await signEd25519(host.privateKey, exchangeHash);
  const input = {
    clientIdentification: "SSH-2.0-client",
    serverIdentification: "SSH-2.0-server",
    clientKexInit,
    serverKexInit,
    clientPrivateKey: client.privateKey,
    clientPublicKey: client.publicKey,
    reply: { hostKey: host.publicKey.marshal(), serverPublic: server.publicKey, signature: signature.marshal() },
  };
  const verified = await verifyCurve25519Sha256Reply(input);
  deepStrictEqual(verified.sharedSecret, sharedSecret);
  deepStrictEqual(verified.exchangeHash, exchangeHash);

  const invalid = signature.marshal();
  invalid[invalid.length - 1] ^= 1;
  await rejects(
    () => verifyCurve25519Sha256Reply({ ...input, reply: { ...input.reply, signature: invalid } }),
    SSHKexError,
  );
});
