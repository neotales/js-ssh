import { SSHReader, SSHWriter } from "./wire.ts";

const SSH_MSG_SERVICE_REQUEST = 5;
const SSH_MSG_SERVICE_ACCEPT = 6;
const SSH_MSG_USERAUTH_REQUEST = 50;
const SSH_MSG_USERAUTH_FAILURE = 51;
const SSH_MSG_USERAUTH_SUCCESS = 52;

/** A parsed SSH_MSG_USERAUTH_REQUEST for the `none` method. */
export type SSHUserAuthNoneRequest = {
  username: string;
  service: string;
};

/** A parsed SSH_MSG_USERAUTH_FAILURE. */
export type SSHUserAuthFailure = {
  methods: string[];
  partialSuccess: boolean;
};

/** Error raised when an SSH authentication message is malformed. */
export class SSHAuthError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SSHAuthError";
  }
}

/** Parses SSH_MSG_SERVICE_REQUEST. */
export function parseServiceRequest(payload: Uint8Array): string {
  return parseService(payload, SSH_MSG_SERVICE_REQUEST, "SSH_MSG_SERVICE_REQUEST");
}

/** Formats SSH_MSG_SERVICE_REQUEST. */
export function formatServiceRequest(service: string): Uint8Array {
  return formatService(SSH_MSG_SERVICE_REQUEST, service);
}

/** Parses SSH_MSG_SERVICE_ACCEPT. */
export function parseServiceAccept(payload: Uint8Array): string {
  return parseService(payload, SSH_MSG_SERVICE_ACCEPT, "SSH_MSG_SERVICE_ACCEPT");
}

/** Formats SSH_MSG_SERVICE_ACCEPT. */
export function formatServiceAccept(service: string): Uint8Array {
  return formatService(SSH_MSG_SERVICE_ACCEPT, service);
}

/** Parses an SSH_MSG_USERAUTH_REQUEST whose method is `none`. */
export function parseUserAuthNoneRequest(payload: Uint8Array): SSHUserAuthNoneRequest {
  const reader = new SSHReader(payload);
  if (reader.readByte() !== SSH_MSG_USERAUTH_REQUEST)
    throw new SSHAuthError("expected SSH_MSG_USERAUTH_REQUEST");
  const username = decodeUtf8(reader.readString(), "SSH username");
  const service = decodeName(reader.readString(), "SSH userauth service");
  const method = decodeName(reader.readString(), "SSH userauth method");
  reader.assertDone();
  if (!username)
    throw new SSHAuthError("SSH username must not be empty");
  if (method !== "none")
    throw new SSHAuthError(`expected the none userauth method, received ${method}`);
  return { username, service };
}

/** Formats an SSH_MSG_USERAUTH_REQUEST using the `none` method. */
export function formatUserAuthNoneRequest(request: SSHUserAuthNoneRequest): Uint8Array {
  if (!request.username)
    throw new SSHAuthError("SSH username must not be empty");
  const username = encodeUtf8(request.username, "SSH username");
  const service = encodeName(request.service, "SSH userauth service");
  return new SSHWriter()
    .writeByte(SSH_MSG_USERAUTH_REQUEST)
    .writeString(username)
    .writeString(service)
    .writeString(new TextEncoder().encode("none"))
    .toUint8Array();
}

/** Parses SSH_MSG_USERAUTH_FAILURE. */
export function parseUserAuthFailure(payload: Uint8Array): SSHUserAuthFailure {
  const reader = new SSHReader(payload);
  if (reader.readByte() !== SSH_MSG_USERAUTH_FAILURE)
    throw new SSHAuthError("expected SSH_MSG_USERAUTH_FAILURE");
  const methods = reader.readNameList();
  const partialSuccess = reader.readBoolean();
  reader.assertDone();
  return { methods, partialSuccess };
}

/** Formats SSH_MSG_USERAUTH_FAILURE. */
export function formatUserAuthFailure(failure: SSHUserAuthFailure): Uint8Array {
  return new SSHWriter().writeByte(SSH_MSG_USERAUTH_FAILURE).writeNameList(failure.methods).writeBoolean(
    failure.partialSuccess,
  )
    .toUint8Array();
}

/** Parses SSH_MSG_USERAUTH_SUCCESS. */
export function parseUserAuthSuccess(payload: Uint8Array): void {
  const reader = new SSHReader(payload);
  if (reader.readByte() !== SSH_MSG_USERAUTH_SUCCESS)
    throw new SSHAuthError("expected SSH_MSG_USERAUTH_SUCCESS");
  reader.assertDone();
}

/** Formats SSH_MSG_USERAUTH_SUCCESS. */
export function formatUserAuthSuccess(): Uint8Array {
  return Uint8Array.of(SSH_MSG_USERAUTH_SUCCESS);
}

function parseService(payload: Uint8Array, message: number, name: string): string {
  const reader = new SSHReader(payload);
  if (reader.readByte() !== message)
    throw new SSHAuthError(`expected ${name}`);
  const service = decodeName(reader.readString(), "SSH service");
  reader.assertDone();
  return service;
}

function formatService(message: number, service: string): Uint8Array {
  return new SSHWriter().writeByte(message).writeString(encodeName(service, "SSH service")).toUint8Array();
}

function encodeName(value: string, name: string): Uint8Array {
  if (!value)
    throw new SSHAuthError(`${name} must not be empty`);
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 0x21 || code > 0x7e || code === 0x2c)
      throw new SSHAuthError(`${name} must be printable US-ASCII without commas`);
  }
  return new TextEncoder().encode(value);
}

function decodeName(bytes: Uint8Array, name: string): string {
  let value = "";
  for (const byte of bytes) {
    if (byte < 0x21 || byte > 0x7e || byte === 0x2c)
      throw new SSHAuthError(`${name} must be printable US-ASCII without commas`);
    value += String.fromCharCode(byte);
  }
  if (!value)
    throw new SSHAuthError(`${name} must not be empty`);
  return value;
}

function encodeUtf8(value: string, name: string): Uint8Array {
  if (value.includes("\0"))
    throw new SSHAuthError(`${name} must not contain NUL`);
  return new TextEncoder().encode(value);
}

function decodeUtf8(bytes: Uint8Array, name: string): string {
  let value: string;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new SSHAuthError(`${name} must be valid UTF-8`, { cause: error });
  }
  if (value.includes("\0"))
    throw new SSHAuthError(`${name} must not contain NUL`);
  return value;
}
