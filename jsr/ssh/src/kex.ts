import { SSHReader, SSHWriter } from "./wire.ts";

const SSH_MSG_KEXINIT = 20;

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
