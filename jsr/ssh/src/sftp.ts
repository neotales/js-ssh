import { SSHReader, SSHWriter } from "./wire.ts";

const SSH_FXP_INIT = 1;
const SSH_FXP_VERSION = 2;
const DEFAULT_MAXIMUM_PACKET_LENGTH = 1024 * 1024;

/** One SFTP extension name and its opaque data. */
export type SFTPExtension = {
  name: string;
  data: Uint8Array;
};

/** SSH_FXP_INIT version negotiation packet. */
export type SFTPInit = {
  version: number;
  extensions: readonly SFTPExtension[];
};

/** SSH_FXP_VERSION version negotiation packet. */
export type SFTPVersion = {
  version: number;
  extensions: readonly SFTPExtension[];
};

/** A complete SFTP packet and the input bytes it consumed. */
export type SFTPPacket = {
  type: number;
  payload: Uint8Array;
  consumed: number;
};

/** Error raised when an SFTP packet is malformed or exceeds configured limits. */
export class SFTPError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SFTPError";
  }
}

/** Formats a complete SFTP packet from its message type and type-specific payload. */
export function formatSftpPacket(type: number, payload: Uint8Array): Uint8Array {
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
export function readSftpPacket(
  input: Uint8Array,
  maximumPacketLength = DEFAULT_MAXIMUM_PACKET_LENGTH,
): SFTPPacket | undefined {
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
export function formatSftpInit(init: SFTPInit): Uint8Array {
  return formatSftpPacket(SSH_FXP_INIT, formatVersionPayload(init.version, init.extensions));
}

/** Parses SSH_FXP_INIT, preserving bytes consumed when followed by another SFTP packet. */
export function parseSftpInit(input: Uint8Array): (SFTPInit & { consumed: number }) | undefined {
  const packet = readSftpPacket(input);
  if (!packet)
    return undefined;
  if (packet.type !== SSH_FXP_INIT)
    throw new SFTPError("expected SSH_FXP_INIT");
  return { ...parseVersionPayload(packet.payload), consumed: packet.consumed };
}

/** Formats SSH_FXP_VERSION. */
export function formatSftpVersion(version: SFTPVersion): Uint8Array {
  return formatSftpPacket(SSH_FXP_VERSION, formatVersionPayload(version.version, version.extensions));
}

/** Parses SSH_FXP_VERSION, preserving bytes consumed when followed by another SFTP packet. */
export function parseSftpVersion(input: Uint8Array): (SFTPVersion & { consumed: number }) | undefined {
  const packet = readSftpPacket(input);
  if (!packet)
    return undefined;
  if (packet.type !== SSH_FXP_VERSION)
    throw new SFTPError("expected SSH_FXP_VERSION");
  return { ...parseVersionPayload(packet.payload), consumed: packet.consumed };
}

function formatVersionPayload(version: number, extensions: readonly SFTPExtension[]): Uint8Array {
  const writer = new SSHWriter().writeUint32(version);
  for (const extension of extensions) {
    writer.writeString(encodeExtensionName(extension.name)).writeString(extension.data);
  }
  return writer.toUint8Array();
}

function parseVersionPayload(payload: Uint8Array): { version: number; extensions: SFTPExtension[] } {
  const reader = new SSHReader(payload);
  const version = reader.readUint32();
  const extensions: SFTPExtension[] = [];
  while (reader.remaining > 0) {
    extensions.push({ name: decodeExtensionName(reader.readString()), data: reader.readString() });
  }
  return { version, extensions };
}

function encodeExtensionName(value: string): Uint8Array {
  if (!value)
    throw new SFTPError("SFTP extension names must not be empty");
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 0x21 || code > 0x7e)
      throw new SFTPError("SFTP extension names must use printable US-ASCII");
  }
  return new TextEncoder().encode(value);
}

function decodeExtensionName(bytes: Uint8Array): string {
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
