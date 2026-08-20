import { SSHReader, SSHWriter } from "./wire.ts";

const SSH_MSG_KEXINIT = 20;
const SSH_MSG_NEWKEYS = 21;
const SSH_MSG_KEX_ECDH_INIT = 30;
const SSH_MSG_KEX_ECDH_REPLY = 31;
const X25519_PUBLIC_KEY_LENGTH = 32;

/** SSH_MSG_KEXINIT algorithm proposal. */
export type SSHKexInit = {
  cookie: Uint8Array;
  kexAlgorithms: readonly string[];
  serverHostKeyAlgorithms: readonly string[];
  encryptionAlgorithmsClientToServer: readonly string[];
  encryptionAlgorithmsServerToClient: readonly string[];
  macAlgorithmsClientToServer: readonly string[];
  macAlgorithmsServerToClient: readonly string[];
  compressionAlgorithmsClientToServer: readonly string[];
  compressionAlgorithmsServerToClient: readonly string[];
  languagesClientToServer: readonly string[];
  languagesServerToClient: readonly string[];
  firstKexPacketFollows: boolean;
};

/** Algorithms selected from client and server SSH_MSG_KEXINIT proposals. */
export type SSHKexSelection = {
  kexAlgorithm: string;
  serverHostKeyAlgorithm: string;
  encryptionAlgorithmClientToServer: string;
  encryptionAlgorithmServerToClient: string;
  macAlgorithmClientToServer: string;
  macAlgorithmServerToClient: string;
  compressionAlgorithmClientToServer: string;
  compressionAlgorithmServerToClient: string;
  languageClientToServer?: string;
  languageServerToClient?: string;
};

/** Fields carried by SSH_MSG_KEX_ECDH_REPLY. */
export type SSHKexEcdhReply = {
  hostKey: Uint8Array;
  serverPublic: Uint8Array;
  signature: Uint8Array;
};

/** An X25519 private CryptoKey and its 32-byte SSH wire public key. */
export type SSHX25519KeyPair = {
  privateKey: CryptoKey;
  publicKey: Uint8Array;
};

/** Error raised when an SSH key-exchange message is malformed. */
export class SSHKexError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SSHKexError";
  }
}

/** Parses a complete SSH_MSG_KEXINIT payload. */
export function parseKexInit(payload: Uint8Array): SSHKexInit {
  const reader = new SSHReader(payload);
  if (reader.readByte() !== SSH_MSG_KEXINIT)
    throw new SSHKexError("expected SSH_MSG_KEXINIT");
  const cookie = new Uint8Array(16);
  for (let index = 0; index < cookie.length; index++) {
    cookie[index] = reader.readByte();
  }
  const init: SSHKexInit = {
    cookie,
    kexAlgorithms: reader.readNameList(),
    serverHostKeyAlgorithms: reader.readNameList(),
    encryptionAlgorithmsClientToServer: reader.readNameList(),
    encryptionAlgorithmsServerToClient: reader.readNameList(),
    macAlgorithmsClientToServer: reader.readNameList(),
    macAlgorithmsServerToClient: reader.readNameList(),
    compressionAlgorithmsClientToServer: reader.readNameList(),
    compressionAlgorithmsServerToClient: reader.readNameList(),
    languagesClientToServer: reader.readNameList(),
    languagesServerToClient: reader.readNameList(),
    firstKexPacketFollows: reader.readBoolean(),
  };
  if (reader.readUint32() !== 0)
    throw new SSHKexError("SSH_MSG_KEXINIT reserved field must be zero");
  reader.assertDone();
  validateKexInit(init);
  return init;
}

/** Parses SSH_MSG_KEX_ECDH_INIT and returns the client's encoded public key. */
export function parseKexEcdhInit(payload: Uint8Array): Uint8Array {
  const reader = new SSHReader(payload);
  if (reader.readByte() !== SSH_MSG_KEX_ECDH_INIT)
    throw new SSHKexError("expected SSH_MSG_KEX_ECDH_INIT");
  const clientPublic = reader.readString();
  reader.assertDone();
  assertNonEmptyBytes(clientPublic, "client public key");
  return clientPublic;
}

/** Formats SSH_MSG_KEX_ECDH_INIT from a client's encoded public key. */
export function formatKexEcdhInit(clientPublic: Uint8Array): Uint8Array {
  assertNonEmptyBytes(clientPublic, "client public key");
  return new SSHWriter().writeByte(SSH_MSG_KEX_ECDH_INIT).writeString(clientPublic).toUint8Array();
}

/** Parses SSH_MSG_KEX_ECDH_REPLY. */
export function parseKexEcdhReply(payload: Uint8Array): SSHKexEcdhReply {
  const reader = new SSHReader(payload);
  if (reader.readByte() !== SSH_MSG_KEX_ECDH_REPLY)
    throw new SSHKexError("expected SSH_MSG_KEX_ECDH_REPLY");
  const reply = { hostKey: reader.readString(), serverPublic: reader.readString(), signature: reader.readString() };
  reader.assertDone();
  assertNonEmptyBytes(reply.hostKey, "server host key");
  assertNonEmptyBytes(reply.serverPublic, "server public key");
  assertNonEmptyBytes(reply.signature, "exchange signature");
  return reply;
}

/** Formats SSH_MSG_KEX_ECDH_REPLY. */
export function formatKexEcdhReply(reply: SSHKexEcdhReply): Uint8Array {
  assertNonEmptyBytes(reply.hostKey, "server host key");
  assertNonEmptyBytes(reply.serverPublic, "server public key");
  assertNonEmptyBytes(reply.signature, "exchange signature");
  return new SSHWriter()
    .writeByte(SSH_MSG_KEX_ECDH_REPLY)
    .writeString(reply.hostKey)
    .writeString(reply.serverPublic)
    .writeString(reply.signature)
    .toUint8Array();
}

/** Parses SSH_MSG_NEWKEYS. */
export function parseNewKeys(payload: Uint8Array): void {
  const reader = new SSHReader(payload);
  if (reader.readByte() !== SSH_MSG_NEWKEYS)
    throw new SSHKexError("expected SSH_MSG_NEWKEYS");
  reader.assertDone();
}

/** Formats SSH_MSG_NEWKEYS. */
export function formatNewKeys(): Uint8Array {
  return Uint8Array.of(SSH_MSG_NEWKEYS);
}

/** Generates an ephemeral X25519 key pair for curve25519-sha256 key exchange. */
export async function generateX25519KeyPair(): Promise<SSHX25519KeyPair> {
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  assertX25519PublicKey(publicKey);
  return { privateKey: pair.privateKey, publicKey };
}

/** Derives the 32-byte X25519 shared secret from an ephemeral private key and peer public key. */
export async function deriveX25519Secret(privateKey: CryptoKey, peerPublicKey: Uint8Array): Promise<Uint8Array> {
  if (privateKey.type !== "private" || privateKey.algorithm.name !== "X25519")
    throw new SSHKexError("expected an X25519 private key");
  assertX25519PublicKey(peerPublicKey);
  const peerBytes = Uint8Array.from(peerPublicKey);
  const peerKey = await crypto.subtle.importKey("raw", peerBytes.buffer, { name: "X25519" }, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: peerKey }, privateKey, 256));
}

/** Formats an SSH_MSG_KEXINIT payload. */
export function formatKexInit(init: SSHKexInit): Uint8Array {
  validateKexInit(init);
  const writer = new SSHWriter().writeByte(SSH_MSG_KEXINIT);
  for (const byte of init.cookie) {
    writer.writeByte(byte);
  }
  writer
    .writeNameList(init.kexAlgorithms)
    .writeNameList(init.serverHostKeyAlgorithms)
    .writeNameList(init.encryptionAlgorithmsClientToServer)
    .writeNameList(init.encryptionAlgorithmsServerToClient)
    .writeNameList(init.macAlgorithmsClientToServer)
    .writeNameList(init.macAlgorithmsServerToClient)
    .writeNameList(init.compressionAlgorithmsClientToServer)
    .writeNameList(init.compressionAlgorithmsServerToClient)
    .writeNameList(init.languagesClientToServer)
    .writeNameList(init.languagesServerToClient)
    .writeBoolean(init.firstKexPacketFollows)
    .writeUint32(0);
  return writer.toUint8Array();
}

/** Selects algorithms using the client proposal's preference order. */
export function negotiateKexInit(client: SSHKexInit, server: SSHKexInit): SSHKexSelection {
  return {
    kexAlgorithm: selectRequired(client.kexAlgorithms, server.kexAlgorithms, "key exchange"),
    serverHostKeyAlgorithm: selectRequired(
      client.serverHostKeyAlgorithms,
      server.serverHostKeyAlgorithms,
      "server host key",
    ),
    encryptionAlgorithmClientToServer: selectRequired(
      client.encryptionAlgorithmsClientToServer,
      server.encryptionAlgorithmsClientToServer,
      "client-to-server encryption",
    ),
    encryptionAlgorithmServerToClient: selectRequired(
      client.encryptionAlgorithmsServerToClient,
      server.encryptionAlgorithmsServerToClient,
      "server-to-client encryption",
    ),
    macAlgorithmClientToServer: selectRequired(
      client.macAlgorithmsClientToServer,
      server.macAlgorithmsClientToServer,
      "client-to-server MAC",
    ),
    macAlgorithmServerToClient: selectRequired(
      client.macAlgorithmsServerToClient,
      server.macAlgorithmsServerToClient,
      "server-to-client MAC",
    ),
    compressionAlgorithmClientToServer: selectRequired(
      client.compressionAlgorithmsClientToServer,
      server.compressionAlgorithmsClientToServer,
      "client-to-server compression",
    ),
    compressionAlgorithmServerToClient: selectRequired(
      client.compressionAlgorithmsServerToClient,
      server.compressionAlgorithmsServerToClient,
      "server-to-client compression",
    ),
    languageClientToServer: selectOptional(client.languagesClientToServer, server.languagesClientToServer),
    languageServerToClient: selectOptional(client.languagesServerToClient, server.languagesServerToClient),
  };
}

/** Reports whether a proposal's first key-exchange and host-key choices match the negotiated result. */
export function isKexGuessCorrect(proposal: SSHKexInit, selection: SSHKexSelection): boolean {
  return proposal.kexAlgorithms[0] === selection.kexAlgorithm &&
    proposal.serverHostKeyAlgorithms[0] === selection.serverHostKeyAlgorithm;
}

function validateKexInit(init: SSHKexInit): void {
  if (init.cookie.length !== 16)
    throw new SSHKexError("SSH_MSG_KEXINIT cookie must contain exactly 16 bytes");
  assertNonEmpty(init.kexAlgorithms, "key exchange");
  assertNonEmpty(init.serverHostKeyAlgorithms, "server host key");
  assertNonEmpty(init.encryptionAlgorithmsClientToServer, "client-to-server encryption");
  assertNonEmpty(init.encryptionAlgorithmsServerToClient, "server-to-client encryption");
  assertNonEmpty(init.macAlgorithmsClientToServer, "client-to-server MAC");
  assertNonEmpty(init.macAlgorithmsServerToClient, "server-to-client MAC");
  assertNonEmpty(init.compressionAlgorithmsClientToServer, "client-to-server compression");
  assertNonEmpty(init.compressionAlgorithmsServerToClient, "server-to-client compression");
}

function assertNonEmpty(value: readonly string[], name: string): void {
  if (value.length === 0)
    throw new SSHKexError(`SSH_MSG_KEXINIT ${name} algorithms must not be empty`);
}

function selectRequired(client: readonly string[], server: readonly string[], name: string): string {
  const selected = selectOptional(client, server);
  if (selected === undefined)
    throw new SSHKexError(`SSH_MSG_KEXINIT has no shared ${name} algorithm`);
  return selected;
}

function selectOptional(client: readonly string[], server: readonly string[]): string | undefined {
  for (const algorithm of client) {
    if (server.includes(algorithm))
      return algorithm;
  }
  return undefined;
}

function assertNonEmptyBytes(value: Uint8Array, name: string): void {
  if (value.length === 0)
    throw new SSHKexError(`SSH ${name} must not be empty`);
}

function assertX25519PublicKey(value: Uint8Array): void {
  if (value.length !== X25519_PUBLIC_KEY_LENGTH)
    throw new SSHKexError("X25519 public keys must contain exactly 32 bytes");
}
