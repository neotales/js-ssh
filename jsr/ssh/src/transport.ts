import { SSHReader, SSHWriter } from "./wire.ts";

const SSH_MSG_DISCONNECT = 1;
const SSH_MSG_IGNORE = 2;
const SSH_MSG_UNIMPLEMENTED = 3;
const SSH_MSG_DEBUG = 4;

/** SSH_MSG_DISCONNECT content. */
export type SSHDisconnect = {
  reasonCode: number;
  description: string;
  languageTag: string;
};

/** SSH_MSG_DEBUG content. */
export type SSHDebug = {
  alwaysDisplay: boolean;
  message: string;
  languageTag: string;
};

/** Error raised when an SSH transport-control message is malformed. */
export class SSHTransportError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SSHTransportError";
  }
}

/** Formats SSH_MSG_DISCONNECT. */
export function formatDisconnect(disconnect: SSHDisconnect): Uint8Array {
  return new SSHWriter()
    .writeByte(SSH_MSG_DISCONNECT)
    .writeUint32(disconnect.reasonCode)
    .writeString(encodeUtf8(disconnect.description, "SSH disconnect description"))
    .writeString(encodeLanguageTag(disconnect.languageTag))
    .toUint8Array();
}

/** Parses SSH_MSG_DISCONNECT. */
export function parseDisconnect(payload: Uint8Array): SSHDisconnect {
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
export function formatIgnore(data: Uint8Array): Uint8Array {
  return new SSHWriter().writeByte(SSH_MSG_IGNORE).writeString(data).toUint8Array();
}

/** Parses SSH_MSG_IGNORE. */
export function parseIgnore(payload: Uint8Array): Uint8Array {
  const reader = new SSHReader(payload);
  expectMessage(reader, SSH_MSG_IGNORE, "SSH_MSG_IGNORE");
  const data = reader.readString();
  reader.assertDone();
  return data;
}

/** Formats SSH_MSG_UNIMPLEMENTED. */
export function formatUnimplemented(packetSequence: number): Uint8Array {
  return new SSHWriter().writeByte(SSH_MSG_UNIMPLEMENTED).writeUint32(packetSequence).toUint8Array();
}

/** Parses SSH_MSG_UNIMPLEMENTED. */
export function parseUnimplemented(payload: Uint8Array): number {
  const reader = new SSHReader(payload);
  expectMessage(reader, SSH_MSG_UNIMPLEMENTED, "SSH_MSG_UNIMPLEMENTED");
  const packetSequence = reader.readUint32();
  reader.assertDone();
  return packetSequence;
}

/** Formats SSH_MSG_DEBUG. */
export function formatDebug(debug: SSHDebug): Uint8Array {
  return new SSHWriter()
    .writeByte(SSH_MSG_DEBUG)
    .writeBoolean(debug.alwaysDisplay)
    .writeString(encodeUtf8(debug.message, "SSH debug message"))
    .writeString(encodeLanguageTag(debug.languageTag))
    .toUint8Array();
}

/** Parses SSH_MSG_DEBUG. */
export function parseDebug(payload: Uint8Array): SSHDebug {
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

function expectMessage(reader: SSHReader, message: number, name: string): void {
  if (reader.readByte() !== message)
    throw new SSHTransportError(`expected ${name}`);
}

function encodeUtf8(value: string, name: string): Uint8Array {
  if (value.includes("\0"))
    throw new SSHTransportError(`${name} must not contain NUL`);
  return new TextEncoder().encode(value);
}

function decodeUtf8(bytes: Uint8Array, name: string): string {
  let value: string;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new SSHTransportError(`${name} must be valid UTF-8`, { cause: error });
  }
  if (value.includes("\0"))
    throw new SSHTransportError(`${name} must not contain NUL`);
  return value;
}

function encodeLanguageTag(value: string): Uint8Array {
  if (!value)
    return new Uint8Array();
  return new TextEncoder().encode(value);
}

function decodeLanguageTag(bytes: Uint8Array): string {
  return decodeUtf8(bytes, "SSH language tag");
}
