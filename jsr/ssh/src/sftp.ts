import { SSHReader, SSHWriter } from "./wire.ts";

const SSH_FXP_INIT = 1;
const SSH_FXP_VERSION = 2;
const SSH_FXP_OPEN = 3;
const SSH_FXP_CLOSE = 4;
const SSH_FXP_READ = 5;
const SSH_FXP_WRITE = 6;
const SSH_FXP_STAT = 17;
const SSH_FXP_STATUS = 101;
const SSH_FXP_HANDLE = 102;
const SSH_FXP_DATA = 103;
const SSH_FXP_ATTRS = 105;
const SSH_FILEXFER_ATTR_SIZE = 0x0000_0001;
const SSH_FILEXFER_ATTR_UIDGID = 0x0000_0002;
const SSH_FILEXFER_ATTR_PERMISSIONS = 0x0000_0004;
const SSH_FILEXFER_ATTR_ACMODTIME = 0x0000_0008;
const SSH_FILEXFER_ATTR_EXTENDED = 0x8000_0000;
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

/** SSH_FXP_WRITE request. */
export type SFTPWriteRequest = {
  id: number;
  handle: Uint8Array;
  offset: bigint;
  data: Uint8Array;
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

/** One extended SFTP v3 attribute. */
export type SFTPExtendedAttribute = {
  type: string;
  data: Uint8Array;
};

/** SFTP v3 file attributes. Paired fields must be specified together. */
export type SFTPAttributes = {
  size?: bigint;
  uid?: number;
  gid?: number;
  permissions?: number;
  atime?: number;
  mtime?: number;
  extended?: readonly SFTPExtendedAttribute[];
};

/** SSH_FXP_STAT request. */
export type SFTPStatRequest = {
  id: number;
  path: string;
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

/** Formats SSH_FXP_WRITE. */
export function formatSftpWriteRequest(request: SFTPWriteRequest): Uint8Array {
  return formatSftpPacket(
    SSH_FXP_WRITE,
    new SSHWriter()
      .writeUint32(request.id)
      .writeString(requireHandle(request.handle))
      .writeUint64(request.offset)
      .writeString(request.data)
      .toUint8Array(),
  );
}

/** Parses SSH_FXP_WRITE. */
export function parseSftpWriteRequest(input: Uint8Array): (SFTPWriteRequest & { consumed: number }) | undefined {
  const packet = expectPacket(input, SSH_FXP_WRITE, "SSH_FXP_WRITE");
  if (!packet)
    return undefined;
  const reader = new SSHReader(packet.payload);
  const request = {
    id: reader.readUint32(),
    handle: requireHandle(reader.readString()),
    offset: reader.readUint64(),
    data: reader.readString(),
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

/** Formats SSH_FXP_STAT. */
export function formatSftpStatRequest(request: SFTPStatRequest): Uint8Array {
  return formatSftpPacket(
    SSH_FXP_STAT,
    new SSHWriter().writeUint32(request.id).writeString(encodeUtf8(request.path, "SFTP path")).toUint8Array(),
  );
}

/** Parses SSH_FXP_STAT. */
export function parseSftpStatRequest(input: Uint8Array): (SFTPStatRequest & { consumed: number }) | undefined {
  const packet = expectPacket(input, SSH_FXP_STAT, "SSH_FXP_STAT");
  if (!packet)
    return undefined;
  const reader = new SSHReader(packet.payload);
  const request = { id: reader.readUint32(), path: decodeUtf8(reader.readString(), "SFTP path") };
  reader.assertDone();
  return { ...request, consumed: packet.consumed };
}

/** Formats SSH_FXP_ATTRS. */
export function formatSftpAttributes(id: number, attributes: SFTPAttributes): Uint8Array {
  const writer = new SSHWriter().writeUint32(id);
  writeAttributes(writer, attributes);
  return formatSftpPacket(SSH_FXP_ATTRS, writer.toUint8Array());
}

/** Parses SSH_FXP_ATTRS. */
export function parseSftpAttributes(
  input: Uint8Array,
): ({ id: number; attributes: SFTPAttributes; consumed: number }) | undefined {
  const packet = expectPacket(input, SSH_FXP_ATTRS, "SSH_FXP_ATTRS");
  if (!packet)
    return undefined;
  const reader = new SSHReader(packet.payload);
  const id = reader.readUint32();
  const attributes = readAttributes(reader);
  reader.assertDone();
  return { id, attributes, consumed: packet.consumed };
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

function writeAttributes(writer: SSHWriter, attributes: SFTPAttributes): void {
  const hasUidGid = attributes.uid !== undefined || attributes.gid !== undefined;
  if (hasUidGid && (attributes.uid === undefined || attributes.gid === undefined))
    throw new SFTPError("SFTP uid and gid attributes must be specified together");
  const hasTimes = attributes.atime !== undefined || attributes.mtime !== undefined;
  if (hasTimes && (attributes.atime === undefined || attributes.mtime === undefined))
    throw new SFTPError("SFTP atime and mtime attributes must be specified together");
  let flags = 0;
  if (attributes.size !== undefined) flags += SSH_FILEXFER_ATTR_SIZE;
  if (hasUidGid) flags += SSH_FILEXFER_ATTR_UIDGID;
  if (attributes.permissions !== undefined) flags += SSH_FILEXFER_ATTR_PERMISSIONS;
  if (hasTimes) flags += SSH_FILEXFER_ATTR_ACMODTIME;
  if (attributes.extended && attributes.extended.length > 0) flags += SSH_FILEXFER_ATTR_EXTENDED;
  writer.writeUint32(flags);
  if (attributes.size !== undefined) writer.writeUint64(attributes.size);
  if (hasUidGid) writer.writeUint32(attributes.uid!).writeUint32(attributes.gid!);
  if (attributes.permissions !== undefined) writer.writeUint32(attributes.permissions);
  if (hasTimes) writer.writeUint32(attributes.atime!).writeUint32(attributes.mtime!);
  if (attributes.extended && attributes.extended.length > 0) {
    writer.writeUint32(attributes.extended.length);
    for (const extension of attributes.extended) {
      writer.writeString(encodeUtf8(extension.type, "SFTP extended attribute type")).writeString(extension.data);
    }
  }
}

function readAttributes(reader: SSHReader): SFTPAttributes {
  const flags = reader.readUint32();
  const knownFlags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID | SSH_FILEXFER_ATTR_PERMISSIONS |
    SSH_FILEXFER_ATTR_ACMODTIME | SSH_FILEXFER_ATTR_EXTENDED;
  if ((flags & ~knownFlags) !== 0)
    throw new SFTPError("SFTP attributes contain unsupported flags");
  const attributes: SFTPAttributes = {};
  if ((flags & SSH_FILEXFER_ATTR_SIZE) !== 0) attributes.size = reader.readUint64();
  if ((flags & SSH_FILEXFER_ATTR_UIDGID) !== 0) {
    attributes.uid = reader.readUint32();
    attributes.gid = reader.readUint32();
  }
  if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) !== 0) attributes.permissions = reader.readUint32();
  if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) !== 0) {
    attributes.atime = reader.readUint32();
    attributes.mtime = reader.readUint32();
  }
  if ((flags & SSH_FILEXFER_ATTR_EXTENDED) !== 0) {
    const count = reader.readUint32();
    const extended: SFTPExtendedAttribute[] = [];
    for (let index = 0; index < count; index++) {
      extended.push({
        type: decodeUtf8(reader.readString(), "SFTP extended attribute type"),
        data: reader.readString(),
      });
    }
    attributes.extended = extended;
  }
  return attributes;
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
