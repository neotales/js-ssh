import { SSHReader, SSHWriter } from "./wire.js";
const SSH_FXP_INIT = 1;
const SSH_FXP_VERSION = 2;
const DEFAULT_MAXIMUM_PACKET_LENGTH = 1024 * 1024;
/** Error raised when an SFTP packet is malformed or exceeds configured limits. */
export class SFTPError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SFTPError";
    }
}
/** Formats a complete SFTP packet from its message type and type-specific payload. */
export function formatSftpPacket(type, payload) {
    if (!Number.isInteger(type) || type < 1 || type > 0xff)
        throw new SFTPError("SFTP packet types must be integers between 1 and 255");
    if (payload.length > 0xffff_fffe)
        throw new SFTPError("SFTP packet payload is too large");
    const packet = new Uint8Array(5 + payload.length);
    new DataView(packet.buffer).setUint32(0, 1 + payload.length);
    packet[4] = type;
    packet.set(payload, 5);
    return packet;
}
/** Reads one complete SFTP packet, returning undefined when more input is required. */
export function readSftpPacket(input, maximumPacketLength = DEFAULT_MAXIMUM_PACKET_LENGTH) {
    if (!Number.isSafeInteger(maximumPacketLength) || maximumPacketLength < 1 || maximumPacketLength > 0xffff_ffff) {
        throw new SFTPError("maximum SFTP packet length must be an integer between 1 and 2^32 - 1");
    }
    if (input.length < 4)
        return undefined;
    const length = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(0);
    if (length < 1)
        throw new SFTPError("SFTP packet length must include a message type");
    if (length > maximumPacketLength)
        throw new SFTPError("SFTP packet length exceeds the configured maximum");
    if (input.length < 4 + length)
        return undefined;
    return { type: input[4], payload: input.slice(5, 4 + length), consumed: 4 + length };
}
/** Formats SSH_FXP_INIT. */
export function formatSftpInit(init) {
    return formatSftpPacket(SSH_FXP_INIT, formatVersionPayload(init.version, init.extensions));
}
/** Parses SSH_FXP_INIT, preserving bytes consumed when followed by another SFTP packet. */
export function parseSftpInit(input) {
    const packet = readSftpPacket(input);
    if (!packet)
        return undefined;
    if (packet.type !== SSH_FXP_INIT)
        throw new SFTPError("expected SSH_FXP_INIT");
    return { ...parseVersionPayload(packet.payload), consumed: packet.consumed };
}
/** Formats SSH_FXP_VERSION. */
export function formatSftpVersion(version) {
    return formatSftpPacket(SSH_FXP_VERSION, formatVersionPayload(version.version, version.extensions));
}
/** Parses SSH_FXP_VERSION, preserving bytes consumed when followed by another SFTP packet. */
export function parseSftpVersion(input) {
    const packet = readSftpPacket(input);
    if (!packet)
        return undefined;
    if (packet.type !== SSH_FXP_VERSION)
        throw new SFTPError("expected SSH_FXP_VERSION");
    return { ...parseVersionPayload(packet.payload), consumed: packet.consumed };
}
function formatVersionPayload(version, extensions) {
    const writer = new SSHWriter().writeUint32(version);
    for (const extension of extensions) {
        writer.writeString(encodeExtensionName(extension.name)).writeString(extension.data);
    }
    return writer.toUint8Array();
}
function parseVersionPayload(payload) {
    const reader = new SSHReader(payload);
    const version = reader.readUint32();
    const extensions = [];
    while (reader.remaining > 0) {
        extensions.push({ name: decodeExtensionName(reader.readString()), data: reader.readString() });
    }
    return { version, extensions };
}
function encodeExtensionName(value) {
    if (!value)
        throw new SFTPError("SFTP extension names must not be empty");
    for (let index = 0; index < value.length; index++) {
        const code = value.charCodeAt(index);
        if (code < 0x21 || code > 0x7e)
            throw new SFTPError("SFTP extension names must use printable US-ASCII");
    }
    return new TextEncoder().encode(value);
}
function decodeExtensionName(bytes) {
    let value = "";
    for (const byte of bytes) {
        if (byte < 0x21 || byte > 0x7e)
            throw new SFTPError("SFTP extension names must use printable US-ASCII");
        value += String.fromCharCode(byte);
    }
    if (!value)
        throw new SFTPError("SFTP extension names must not be empty");
    return value;
}
