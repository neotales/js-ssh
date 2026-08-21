import { SSHReader, SSHWriter } from "./primitives.js";
const SSH_MSG_CHANNEL_OPEN = 90;
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
const SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
const SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
const SSH_MSG_CHANNEL_DATA = 94;
const SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
const SSH_MSG_CHANNEL_EOF = 96;
const SSH_MSG_CHANNEL_CLOSE = 97;
const SSH_MSG_CHANNEL_REQUEST = 98;
const SSH_MSG_CHANNEL_SUCCESS = 99;
const SSH_MSG_CHANNEL_FAILURE = 100;
/** Error raised when an SSH connection-protocol message is malformed. */
export class SSHConnectionError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHConnectionError";
    }
}
/** Formats SSH_MSG_CHANNEL_OPEN for a `session` channel. */
export function formatSessionChannelOpen(open) {
    validateWindow(open.initialWindowSize, "initial window size");
    validateWindow(open.maximumPacketSize, "maximum packet size");
    return new SSHWriter()
        .writeByte(SSH_MSG_CHANNEL_OPEN)
        .writeString(new TextEncoder().encode("session"))
        .writeUint32(open.senderChannel)
        .writeUint32(open.initialWindowSize)
        .writeUint32(open.maximumPacketSize)
        .toUint8Array();
}
/** Parses SSH_MSG_CHANNEL_OPEN for a `session` channel. */
export function parseSessionChannelOpen(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_CHANNEL_OPEN, "SSH_MSG_CHANNEL_OPEN");
    if (decodeName(reader.readString(), "SSH channel type") !== "session")
        throw new SSHConnectionError("expected an SSH session channel");
    const open = {
        senderChannel: reader.readUint32(),
        initialWindowSize: reader.readUint32(),
        maximumPacketSize: reader.readUint32(),
    };
    reader.assertDone();
    validateWindow(open.initialWindowSize, "initial window size");
    validateWindow(open.maximumPacketSize, "maximum packet size");
    return open;
}
/** Formats SSH_MSG_CHANNEL_OPEN_CONFIRMATION. */
export function formatChannelOpenConfirmation(confirmation) {
    validateWindow(confirmation.initialWindowSize, "initial window size");
    validateWindow(confirmation.maximumPacketSize, "maximum packet size");
    return new SSHWriter()
        .writeByte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .writeUint32(confirmation.recipientChannel)
        .writeUint32(confirmation.senderChannel)
        .writeUint32(confirmation.initialWindowSize)
        .writeUint32(confirmation.maximumPacketSize)
        .toUint8Array();
}
/** Parses SSH_MSG_CHANNEL_OPEN_CONFIRMATION. */
export function parseChannelOpenConfirmation(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, "SSH_MSG_CHANNEL_OPEN_CONFIRMATION");
    const confirmation = {
        recipientChannel: reader.readUint32(),
        senderChannel: reader.readUint32(),
        initialWindowSize: reader.readUint32(),
        maximumPacketSize: reader.readUint32(),
    };
    reader.assertDone();
    validateWindow(confirmation.initialWindowSize, "initial window size");
    validateWindow(confirmation.maximumPacketSize, "maximum packet size");
    return confirmation;
}
/** Formats SSH_MSG_CHANNEL_OPEN_FAILURE. */
export function formatChannelOpenFailure(failure) {
    return new SSHWriter()
        .writeByte(SSH_MSG_CHANNEL_OPEN_FAILURE)
        .writeUint32(failure.recipientChannel)
        .writeUint32(failure.reasonCode)
        .writeString(encodeUtf8(failure.description, "SSH channel failure description"))
        .writeString(encodeLanguageTag(failure.languageTag))
        .toUint8Array();
}
/** Parses SSH_MSG_CHANNEL_OPEN_FAILURE. */
export function parseChannelOpenFailure(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_CHANNEL_OPEN_FAILURE, "SSH_MSG_CHANNEL_OPEN_FAILURE");
    const failure = {
        recipientChannel: reader.readUint32(),
        reasonCode: reader.readUint32(),
        description: decodeUtf8(reader.readString(), "SSH channel failure description"),
        languageTag: decodeLanguageTag(reader.readString()),
    };
    reader.assertDone();
    return failure;
}
/** Formats SSH_MSG_CHANNEL_WINDOW_ADJUST. */
export function formatChannelWindowAdjust(adjust) {
    if (adjust.bytesToAdd === 0)
        throw new SSHConnectionError("SSH channel window adjustment must not be zero");
    return new SSHWriter()
        .writeByte(SSH_MSG_CHANNEL_WINDOW_ADJUST)
        .writeUint32(adjust.recipientChannel)
        .writeUint32(adjust.bytesToAdd)
        .toUint8Array();
}
/** Parses SSH_MSG_CHANNEL_WINDOW_ADJUST. */
export function parseChannelWindowAdjust(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_CHANNEL_WINDOW_ADJUST, "SSH_MSG_CHANNEL_WINDOW_ADJUST");
    const adjust = { recipientChannel: reader.readUint32(), bytesToAdd: reader.readUint32() };
    reader.assertDone();
    if (adjust.bytesToAdd === 0)
        throw new SSHConnectionError("SSH channel window adjustment must not be zero");
    return adjust;
}
/** Formats SSH_MSG_CHANNEL_DATA. */
export function formatChannelData(data) {
    return new SSHWriter().writeByte(SSH_MSG_CHANNEL_DATA).writeUint32(data.recipientChannel).writeString(data.data)
        .toUint8Array();
}
/** Parses SSH_MSG_CHANNEL_DATA. */
export function parseChannelData(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_CHANNEL_DATA, "SSH_MSG_CHANNEL_DATA");
    const data = { recipientChannel: reader.readUint32(), data: reader.readString() };
    reader.assertDone();
    return data;
}
/** Formats SSH_MSG_CHANNEL_EXTENDED_DATA. */
export function formatChannelExtendedData(data) {
    return new SSHWriter()
        .writeByte(SSH_MSG_CHANNEL_EXTENDED_DATA)
        .writeUint32(data.recipientChannel)
        .writeUint32(data.dataTypeCode)
        .writeString(data.data)
        .toUint8Array();
}
/** Parses SSH_MSG_CHANNEL_EXTENDED_DATA. */
export function parseChannelExtendedData(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_CHANNEL_EXTENDED_DATA, "SSH_MSG_CHANNEL_EXTENDED_DATA");
    const data = { recipientChannel: reader.readUint32(), dataTypeCode: reader.readUint32(), data: reader.readString() };
    reader.assertDone();
    return data;
}
/** Formats SSH_MSG_CHANNEL_EOF. */
export function formatChannelEof(recipientChannel) {
    return formatChannelIdMessage(SSH_MSG_CHANNEL_EOF, recipientChannel);
}
/** Parses SSH_MSG_CHANNEL_EOF. */
export function parseChannelEof(payload) {
    return parseChannelIdMessage(payload, SSH_MSG_CHANNEL_EOF, "SSH_MSG_CHANNEL_EOF");
}
/** Formats SSH_MSG_CHANNEL_CLOSE. */
export function formatChannelClose(recipientChannel) {
    return formatChannelIdMessage(SSH_MSG_CHANNEL_CLOSE, recipientChannel);
}
/** Parses SSH_MSG_CHANNEL_CLOSE. */
export function parseChannelClose(payload) {
    return parseChannelIdMessage(payload, SSH_MSG_CHANNEL_CLOSE, "SSH_MSG_CHANNEL_CLOSE");
}
/** Formats an SSH `exec` channel request. */
export function formatExecChannelRequest(request) {
    return new SSHWriter()
        .writeByte(SSH_MSG_CHANNEL_REQUEST)
        .writeUint32(request.recipientChannel)
        .writeString(new TextEncoder().encode("exec"))
        .writeBoolean(request.wantReply)
        .writeString(encodeUtf8(request.command, "SSH exec command"))
        .toUint8Array();
}
/** Parses an SSH `exec` channel request. */
export function parseExecChannelRequest(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_CHANNEL_REQUEST, "SSH_MSG_CHANNEL_REQUEST");
    const request = {
        recipientChannel: reader.readUint32(),
        requestType: decodeName(reader.readString(), "SSH channel request type"),
        wantReply: reader.readBoolean(),
        command: decodeUtf8(reader.readString(), "SSH exec command"),
    };
    reader.assertDone();
    if (request.requestType !== "exec")
        throw new SSHConnectionError(`expected an SSH exec request, received ${request.requestType}`);
    return { recipientChannel: request.recipientChannel, wantReply: request.wantReply, command: request.command };
}
/** Formats an SSH `exit-status` channel request. */
export function formatExitStatus(status) {
    return new SSHWriter()
        .writeByte(SSH_MSG_CHANNEL_REQUEST)
        .writeUint32(status.recipientChannel)
        .writeString(new TextEncoder().encode("exit-status"))
        .writeBoolean(false)
        .writeUint32(status.status)
        .toUint8Array();
}
/** Parses an SSH `exit-status` channel request. */
export function parseExitStatus(payload) {
    const reader = new SSHReader(payload);
    expectMessage(reader, SSH_MSG_CHANNEL_REQUEST, "SSH_MSG_CHANNEL_REQUEST");
    const recipientChannel = reader.readUint32();
    const requestType = decodeName(reader.readString(), "SSH channel request type");
    const wantReply = reader.readBoolean();
    const status = reader.readUint32();
    reader.assertDone();
    if (requestType !== "exit-status")
        throw new SSHConnectionError(`expected an SSH exit-status request, received ${requestType}`);
    if (wantReply)
        throw new SSHConnectionError("SSH exit-status requests must not request a reply");
    return { recipientChannel, status };
}
/** Formats SSH_MSG_CHANNEL_SUCCESS. */
export function formatChannelRequestSuccess(recipientChannel) {
    return formatChannelIdMessage(SSH_MSG_CHANNEL_SUCCESS, recipientChannel);
}
/** Parses SSH_MSG_CHANNEL_SUCCESS. */
export function parseChannelRequestSuccess(payload) {
    return parseChannelIdMessage(payload, SSH_MSG_CHANNEL_SUCCESS, "SSH_MSG_CHANNEL_SUCCESS");
}
/** Formats SSH_MSG_CHANNEL_FAILURE. */
export function formatChannelRequestFailure(recipientChannel) {
    return formatChannelIdMessage(SSH_MSG_CHANNEL_FAILURE, recipientChannel);
}
/** Parses SSH_MSG_CHANNEL_FAILURE. */
export function parseChannelRequestFailure(payload) {
    return parseChannelIdMessage(payload, SSH_MSG_CHANNEL_FAILURE, "SSH_MSG_CHANNEL_FAILURE");
}
function expectMessage(reader, message, name) {
    if (reader.readByte() !== message)
        throw new SSHConnectionError(`expected ${name}`);
}
function validateWindow(value, name) {
    if (value === 0)
        throw new SSHConnectionError(`SSH ${name} must not be zero`);
}
function formatChannelIdMessage(message, recipientChannel) {
    return new SSHWriter().writeByte(message).writeUint32(recipientChannel).toUint8Array();
}
function parseChannelIdMessage(payload, message, name) {
    const reader = new SSHReader(payload);
    expectMessage(reader, message, name);
    const recipientChannel = reader.readUint32();
    reader.assertDone();
    return recipientChannel;
}
function decodeName(bytes, name) {
    let value = "";
    for (const byte of bytes) {
        if (byte < 0x21 || byte > 0x7e || byte === 0x2c)
            throw new SSHConnectionError(`${name} must be printable US-ASCII without commas`);
        value += String.fromCharCode(byte);
    }
    if (!value)
        throw new SSHConnectionError(`${name} must not be empty`);
    return value;
}
function encodeUtf8(value, name) {
    if (value.includes("\0"))
        throw new SSHConnectionError(`${name} must not contain NUL`);
    return new TextEncoder().encode(value);
}
function decodeUtf8(bytes, name) {
    let value;
    try {
        value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }
    catch (error) {
        throw new SSHConnectionError(`${name} must be valid UTF-8`, { cause: error });
    }
    if (value.includes("\0"))
        throw new SSHConnectionError(`${name} must not contain NUL`);
    return value;
}
function encodeLanguageTag(value) {
    if (!value)
        return new Uint8Array();
    return new TextEncoder().encode(value);
}
function decodeLanguageTag(bytes) {
    return decodeUtf8(bytes, "SSH channel failure language tag");
}
