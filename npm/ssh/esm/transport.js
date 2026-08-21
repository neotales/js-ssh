import { SSHReader, SSHWriter } from "./primitives.js";
const SSH_MSG_DISCONNECT = 1;
const SSH_MSG_IGNORE = 2;
const SSH_MSG_UNIMPLEMENTED = 3;
const SSH_MSG_DEBUG = 4;
/** Error raised when an SSH transport-control message is malformed. */
export class SSHTransportError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHTransportError";
    }
}
/** Formats SSH_MSG_DISCONNECT. */
export function formatDisconnect(disconnect) {
    return new SSHWriter()
        .writeByte(SSH_MSG_DISCONNECT)
        .writeUint32(disconnect.reasonCode)
        .writeString(encodeUtf8(disconnect.description, "SSH disconnect description"))
        .writeString(encodeLanguageTag(disconnect.languageTag))
        .toUint8Array();
}
/** Parses SSH_MSG_DISCONNECT. */
export function parseDisconnect(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_DISCONNECT, "SSH_MSG_DISCONNECT");
    const disconnect = {
        reasonCode: reader.readUint32(),
        description: decodeUtf8(reader.readString(), "SSH disconnect description"),
        languageTag: decodeLanguageTag(reader.readString()),
    };
    reader.assertDone();
    return disconnect;
}
/** Formats SSH_MSG_IGNORE. */
export function formatIgnore(data) {
    return new SSHWriter().writeByte(SSH_MSG_IGNORE).writeString(data).toUint8Array();
}
/** Parses SSH_MSG_IGNORE. */
export function parseIgnore(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_IGNORE, "SSH_MSG_IGNORE");
    const data = reader.readString();
    reader.assertDone();
    return data;
}
/** Formats SSH_MSG_UNIMPLEMENTED. */
export function formatUnimplemented(packetSequence) {
    return new SSHWriter().writeByte(SSH_MSG_UNIMPLEMENTED).writeUint32(packetSequence).toUint8Array();
}
/** Parses SSH_MSG_UNIMPLEMENTED. */
export function parseUnimplemented(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_UNIMPLEMENTED, "SSH_MSG_UNIMPLEMENTED");
    const packetSequence = reader.readUint32();
    reader.assertDone();
    return packetSequence;
}
/** Formats SSH_MSG_DEBUG. */
export function formatDebug(debug) {
    return new SSHWriter()
        .writeByte(SSH_MSG_DEBUG)
        .writeBoolean(debug.alwaysDisplay)
        .writeString(encodeUtf8(debug.message, "SSH debug message"))
        .writeString(encodeLanguageTag(debug.languageTag))
        .toUint8Array();
}
/** Parses SSH_MSG_DEBUG. */
export function parseDebug(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_DEBUG, "SSH_MSG_DEBUG");
    const debug = {
        alwaysDisplay: reader.readBoolean(),
        message: decodeUtf8(reader.readString(), "SSH debug message"),
        languageTag: decodeLanguageTag(reader.readString()),
    };
    reader.assertDone();
    return debug;
}
function expectMessage(reader, message, name) {
    if (reader.readByte() !== message)
        throw new SSHTransportError(`expected ${name}`);
}
function encodeUtf8(value, name) {
    if (value.includes("\0"))
        throw new SSHTransportError(`${name} must not contain NUL`);
    return new TextEncoder().encode(value);
}
function decodeUtf8(bytes, name) {
    let value;
    try {
        value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }
    catch (error) {
        throw new SSHTransportError(`${name} must be valid UTF-8`, { cause: error });
    }
    if (value.includes("\0"))
        throw new SSHTransportError(`${name} must not contain NUL`);
    return value;
}
function encodeLanguageTag(value) {
    if (!value)
        return new Uint8Array();
    return new TextEncoder().encode(value);
}
function decodeLanguageTag(bytes) {
    return decodeUtf8(bytes, "SSH language tag");
}
