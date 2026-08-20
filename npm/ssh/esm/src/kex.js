import { SSHReader, SSHWriter } from "./wire.js";
const SSH_MSG_KEXINIT = 20;
const SSH_MSG_NEWKEYS = 21;
const SSH_MSG_KEX_ECDH_INIT = 30;
const SSH_MSG_KEX_ECDH_REPLY = 31;
const X25519_PUBLIC_KEY_LENGTH = 32;
/** Error raised when an SSH key-exchange message is malformed. */
export class SSHKexError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHKexError";
    }
}
/** Parses a complete SSH_MSG_KEXINIT payload. */
export function parseKexInit(payload) {
    const reader = new SSHReader(payload);
    if (reader.readByte() !== SSH_MSG_KEXINIT)
        throw new SSHKexError("expected SSH_MSG_KEXINIT");
    const cookie = new Uint8Array(16);
    for (let index = 0; index < cookie.length; index++) {
        cookie[index] = reader.readByte();
    }
    const init = {
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
export function parseKexEcdhInit(payload) {
    const reader = new SSHReader(payload);
    if (reader.readByte() !== SSH_MSG_KEX_ECDH_INIT)
        throw new SSHKexError("expected SSH_MSG_KEX_ECDH_INIT");
    const clientPublic = reader.readString();
    reader.assertDone();
    assertNonEmptyBytes(clientPublic, "client public key");
    return clientPublic;
}
/** Formats SSH_MSG_KEX_ECDH_INIT from a client's encoded public key. */
export function formatKexEcdhInit(clientPublic) {
    assertNonEmptyBytes(clientPublic, "client public key");
    return new SSHWriter().writeByte(SSH_MSG_KEX_ECDH_INIT).writeString(clientPublic).toUint8Array();
}
/** Parses SSH_MSG_KEX_ECDH_REPLY. */
export function parseKexEcdhReply(payload) {
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
export function formatKexEcdhReply(reply) {
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
export function parseNewKeys(payload) {
    const reader = new SSHReader(payload);
    if (reader.readByte() !== SSH_MSG_NEWKEYS)
        throw new SSHKexError("expected SSH_MSG_NEWKEYS");
    reader.assertDone();
}
/** Formats SSH_MSG_NEWKEYS. */
export function formatNewKeys() {
    return Uint8Array.of(SSH_MSG_NEWKEYS);
}
/** Generates an ephemeral X25519 key pair for curve25519-sha256 key exchange. */
export async function generateX25519KeyPair() {
    const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    assertX25519PublicKey(publicKey);
    return { privateKey: pair.privateKey, publicKey };
}
/** Derives the 32-byte X25519 shared secret from an ephemeral private key and peer public key. */
export async function deriveX25519Secret(privateKey, peerPublicKey) {
    if (privateKey.type !== "private" || privateKey.algorithm.name !== "X25519")
        throw new SSHKexError("expected an X25519 private key");
    assertX25519PublicKey(peerPublicKey);
    const peerBytes = Uint8Array.from(peerPublicKey);
    const peerKey = await crypto.subtle.importKey("raw", peerBytes.buffer, { name: "X25519" }, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: peerKey }, privateKey, 256));
}
/** Computes the RFC 8731 curve25519-sha256 exchange hash. */
export async function computeCurve25519Sha256ExchangeHash(input) {
    assertIdentification(input.clientIdentification, "client");
    assertIdentification(input.serverIdentification, "server");
    assertNonEmptyBytes(input.clientKexInit, "client KEXINIT");
    assertNonEmptyBytes(input.serverKexInit, "server KEXINIT");
    assertNonEmptyBytes(input.hostKey, "server host key");
    assertX25519PublicKey(input.clientPublic);
    assertX25519PublicKey(input.serverPublic);
    assertX25519PublicKey(input.sharedSecret);
    if (input.sharedSecret.every((byte) => byte === 0))
        throw new SSHKexError("X25519 shared secret must not be all zeroes");
    const encoder = new TextEncoder();
    const encoded = new SSHWriter()
        .writeString(encoder.encode(input.clientIdentification))
        .writeString(encoder.encode(input.serverIdentification))
        .writeString(input.clientKexInit)
        .writeString(input.serverKexInit)
        .writeString(input.hostKey)
        .writeString(input.clientPublic)
        .writeString(input.serverPublic)
        .writeMpint(x25519SecretToMpint(input.sharedSecret))
        .toUint8Array();
    return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(encoded).buffer));
}
/** Expands SHA-256 SSH key material according to RFC 4253 section 7.2. */
export async function deriveKeyMaterial(sharedSecret, exchangeHash, sessionId, label, length) {
    assertX25519PublicKey(sharedSecret);
    if (sharedSecret.every((byte) => byte === 0))
        throw new SSHKexError("X25519 shared secret must not be all zeroes");
    if (exchangeHash.length !== 32 || sessionId.length !== 32)
        throw new SSHKexError("SSH SHA-256 exchange hashes and session IDs must contain exactly 32 bytes");
    if (!Number.isSafeInteger(length) || length < 1)
        throw new SSHKexError("SSH key material length must be a positive safe integer");
    const secret = new SSHWriter().writeMpint(x25519SecretToMpint(sharedSecret)).toUint8Array();
    let material = new Uint8Array();
    while (material.length < length) {
        const seed = new Uint8Array(secret.length + exchangeHash.length + material.length + (material.length === 0 ? 33 : 0));
        let offset = 0;
        seed.set(secret, offset);
        offset += secret.length;
        seed.set(exchangeHash, offset);
        offset += exchangeHash.length;
        if (material.length === 0) {
            seed[offset++] = label.charCodeAt(0);
            seed.set(sessionId, offset);
        }
        else {
            seed.set(material, offset);
        }
        const chunk = new Uint8Array(await crypto.subtle.digest("SHA-256", seed.buffer));
        const expanded = new Uint8Array(material.length + chunk.length);
        expanded.set(material);
        expanded.set(chunk, material.length);
        material = expanded;
    }
    return material.slice(0, length);
}
/** Formats an SSH_MSG_KEXINIT payload. */
export function formatKexInit(init) {
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
export function negotiateKexInit(client, server) {
    return {
        kexAlgorithm: selectRequired(client.kexAlgorithms, server.kexAlgorithms, "key exchange"),
        serverHostKeyAlgorithm: selectRequired(client.serverHostKeyAlgorithms, server.serverHostKeyAlgorithms, "server host key"),
        encryptionAlgorithmClientToServer: selectRequired(client.encryptionAlgorithmsClientToServer, server.encryptionAlgorithmsClientToServer, "client-to-server encryption"),
        encryptionAlgorithmServerToClient: selectRequired(client.encryptionAlgorithmsServerToClient, server.encryptionAlgorithmsServerToClient, "server-to-client encryption"),
        macAlgorithmClientToServer: selectRequired(client.macAlgorithmsClientToServer, server.macAlgorithmsClientToServer, "client-to-server MAC"),
        macAlgorithmServerToClient: selectRequired(client.macAlgorithmsServerToClient, server.macAlgorithmsServerToClient, "server-to-client MAC"),
        compressionAlgorithmClientToServer: selectRequired(client.compressionAlgorithmsClientToServer, server.compressionAlgorithmsClientToServer, "client-to-server compression"),
        compressionAlgorithmServerToClient: selectRequired(client.compressionAlgorithmsServerToClient, server.compressionAlgorithmsServerToClient, "server-to-client compression"),
        languageClientToServer: selectOptional(client.languagesClientToServer, server.languagesClientToServer),
        languageServerToClient: selectOptional(client.languagesServerToClient, server.languagesServerToClient),
    };
}
/** Reports whether a proposal's first key-exchange and host-key choices match the negotiated result. */
export function isKexGuessCorrect(proposal, selection) {
    return proposal.kexAlgorithms[0] === selection.kexAlgorithm &&
        proposal.serverHostKeyAlgorithms[0] === selection.serverHostKeyAlgorithm;
}
function validateKexInit(init) {
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
function assertNonEmpty(value, name) {
    if (value.length === 0)
        throw new SSHKexError(`SSH_MSG_KEXINIT ${name} algorithms must not be empty`);
}
function selectRequired(client, server, name) {
    const selected = selectOptional(client, server);
    if (selected === undefined)
        throw new SSHKexError(`SSH_MSG_KEXINIT has no shared ${name} algorithm`);
    return selected;
}
function selectOptional(client, server) {
    for (const algorithm of client) {
        if (server.includes(algorithm))
            return algorithm;
    }
    return undefined;
}
function assertNonEmptyBytes(value, name) {
    if (value.length === 0)
        throw new SSHKexError(`SSH ${name} must not be empty`);
}
function assertX25519PublicKey(value) {
    if (value.length !== X25519_PUBLIC_KEY_LENGTH)
        throw new SSHKexError("X25519 public keys must contain exactly 32 bytes");
}
function assertIdentification(value, role) {
    if (!value.startsWith("SSH-"))
        throw new SSHKexError(`${role} identification must start with SSH-`);
    for (let index = 0; index < value.length; index++) {
        const code = value.charCodeAt(index);
        if (code < 0x20 || code > 0x7e)
            throw new SSHKexError(`${role} identification must use printable US-ASCII`);
    }
}
function x25519SecretToMpint(secret) {
    let value = 0n;
    for (let index = secret.length - 1; index >= 0; index--) {
        value = (value << 8n) | BigInt(secret[index]);
    }
    return value;
}
