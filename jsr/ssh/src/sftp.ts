import { SSHReader, SSHWriter } from "./wire.ts";

const SSH_FXP_INIT = 1;
const SSH_FXP_VERSION = 2;
const SSH_FXP_OPEN = 3;
const SSH_FXP_CLOSE = 4;
const SSH_FXP_READ = 5;
const SSH_FXP_STATUS = 101;
const SSH_FXP_HANDLE = 102;
const SSH_FXP_DATA = 103;
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

/** SSH_FXP_OPEN request with empty v3 file attributes. */
export type SFTPOpenRequest = {
  id: number;
  path: string;
  pflags: number;
};

/** SSH_FXP_CLOSE request. */
export type SFTPCloseRequest = {
  id: number;
  handle: Uint8Array;
};

/** SSH_FXP_READ request. */
export type SFTPReadRequest = {
  id: number;
  handle: Uint8Array;
  offset: bigint;
  length: number;
};

/** SSH_FXP_HANDLE response. */
export type SFTPHandle = {
  id: number;
  handle: Uint8Array;
};

/** SSH_FXP_DATA response. */
export type SFTPData = {
  id: number;
  data: Uint8Array;
};

/** SSH_FXP_STATUS response. */
export type SFTPStatus = {
  id: number;
  code: number;
  message: string;
  languageTag: string;
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

/** Formats SSH_FXP_OPEN with no file attributes. */
export function formatSftpOpenRequest(request: SFTPOpenRequest): Uint8Array {
  return formatSftpPacket(
    SSH_FXP_OPEN,
    new SSHWriter()
      .writeUint32(request.id)
      .writeString(encodeUtf8(request.path, "SFTP path"))
      .writeUint32(request.pflags)
      .writeUint32(0)
      .toUint8Array(),
  );
}

/** Parses SSH_FXP_OPEN with no file attributes. */
export function parseSftpOpenRequest(input: Uint8Array): (SFTPOpenRequest & { consumed: number }) | undefined {
  const packet = expectPacket(input, SSH_FXP_OPEN, "SSH_FXP_OPEN");
  if (!packet)
    return undefined;
  const reader = new SSHReader(packet.payload);
  const request = {
    id: reader.readUint32(),
    path: decodeUtf8(reader.readString(), "SFTP path"),
    pflags: reader.readUint32(),
  };
  if (reader.readUint32() !== 0)
    throw new SFTPError("SFTP file attributes are not supported for SSH_FXP_OPEN parsing");
  reader.assertDone();
  return { ...request, consumed: packet.consumed };
}

/** Formats SSH_FXP_CLOSE. */
export function formatSftpCloseRequest(request: SFTPCloseRequest): Uint8Array {
  return formatSftpPacket(
    SSH_FXP_CLOSE,
    new SSHWriter().writeUint32(request.id).writeString(requireHandle(request.handle)).toUint8Array(),
  );
}

/** Parses SSH_FXP_CLOSE. */
export function parseSftpCloseRequest(input: Uint8Array): (SFTPCloseRequest & { consumed: number }) | undefined {
  const packet = expectPacket(input, SSH_FXP_CLOSE, "SSH_FXP_CLOSE");
  if (!packet)
    return undefined;
  const reader = new SSHReader(packet.payload);
  const request = { id: reader.readUint32(), handle: requireHandle(reader.readString()) };
  reader.assertDone();
  return { ...request, consumed: packet.consumed };
}

/** Formats SSH_FXP_READ. */
export function formatSftpReadRequest(request: SFTPReadRequest): Uint8Array {
  return formatSftpPacket(
    SSH_FXP_READ,
    new SSHWriter()
      .writeUint32(request.id)
      .writeString(requireHandle(request.handle))
      .writeUint64(request.offset)
      .writeUint32(request.length)
      .toUint8Array(),
  );
}

/** Parses SSH_FXP_READ. */
export function parseSftpReadRequest(input: Uint8Array): (SFTPReadRequest & { consumed: number }) | undefined {
  const packet = expectPacket(input, SSH_FXP_READ, "SSH_FXP_READ");
  if (!packet)
    return undefined;
  const reader = new SSHReader(packet.payload);
  const request = {
    id: reader.readUint32(),
    handle: requireHandle(reader.readString()),
    offset: reader.readUint64(),
    length: reader.readUint32(),
  };
  reader.assertDone();
  return { ...request, consumed: packet.consumed };
}

/** Formats SSH_FXP_HANDLE. */
export function formatSftpHandle(response: SFTPHandle): Uint8Array {
  return formatSftpPacket(
    SSH_FXP_HANDLE,
    new SSHWriter().writeUint32(response.id).writeString(requireHandle(response.handle)).toUint8Array(),
  );
}

/** Parses SSH_FXP_HANDLE. */
export function parseSftpHandle(input: Uint8Array): (SFTPHandle & { consumed: number }) | undefined {
  const packet = expectPacket(input, SSH_FXP_HANDLE, "SSH_FXP_HANDLE");
  if (!packet)
    return undefined;
  const reader = new SSHReader(packet.payload);
  const response = { id: reader.readUint32(), handle: requireHandle(reader.readString()) };
  reader.assertDone();
  return { ...response, consumed: packet.consumed };
}

/** Formats SSH_FXP_DATA. */
export function formatSftpData(response: SFTPData): Uint8Array {
  return formatSftpPacket(
    SSH_FXP_DATA,
    new SSHWriter().writeUint32(response.id).writeString(response.data).toUint8Array(),
  );
}

/** Parses SSH_FXP_DATA. */
export function parseSftpData(input: Uint8Array): (SFTPData & { consumed: number }) | undefined {
  const packet = expectPacket(input, SSH_FXP_DATA, "SSH_FXP_DATA");
  if (!packet)
    return undefined;
  const reader = new SSHReader(packet.payload);
  const response = { id: reader.readUint32(), data: reader.readString() };
  reader.assertDone();
  return { ...response, consumed: packet.consumed };
}

/** Formats SSH_FXP_STATUS. */
export function formatSftpStatus(response: SFTPStatus): Uint8Array {
  return formatSftpPacket(
    SSH_FXP_STATUS,
    new SSHWriter()
      .writeUint32(response.id)
      .writeUint32(response.code)
      .writeString(encodeUtf8(response.message, "SFTP status message"))
      .writeString(encodeUtf8(response.languageTag, "SFTP status language tag"))
      .toUint8Array(),
  );
}

/** Parses SSH_FXP_STATUS. */
export function parseSftpStatus(input: Uint8Array): (SFTPStatus & { consumed: number }) | undefined {
  const packet = expectPacket(input, SSH_FXP_STATUS, "SSH_FXP_STATUS");
  if (!packet)
    return undefined;
  const reader = new SSHReader(packet.payload);
  const response = {
    id: reader.readUint32(),
    code: reader.readUint32(),
    message: decodeUtf8(reader.readString(), "SFTP status message"),
    languageTag: decodeUtf8(reader.readString(), "SFTP status language tag"),
  };
  reader.assertDone();
  return { ...response, consumed: packet.consumed };
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

function expectPacket(input: Uint8Array, type: number, name: string): SFTPPacket | undefined {
  const packet = readSftpPacket(input);
  if (!packet)
    return undefined;
  if (packet.type !== type)
    throw new SFTPError(`expected ${name}`);
  return packet;
}

function requireHandle(handle: Uint8Array): Uint8Array {
  if (handle.length === 0)
    throw new SFTPError("SFTP handles must not be empty");
  return handle;
}

function encodeUtf8(value: string, name: string): Uint8Array {
  if (value.includes("\0"))
    throw new SFTPError(`${name} must not contain NUL`);
  return new TextEncoder().encode(value);
}

function decodeUtf8(bytes: Uint8Array, name: string): string {
  let value: string;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new SFTPError(`${name} must be valid UTF-8`, { cause: error });
  }
  if (value.includes("\0"))
    throw new SFTPError(`${name} must not contain NUL`);
  return value;
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
