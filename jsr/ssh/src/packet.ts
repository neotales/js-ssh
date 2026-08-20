const DEFAULT_BLOCK_SIZE = 8;
const DEFAULT_MAXIMUM_PACKET_LENGTH = 35_000;

/** Bounds used to encode or decode an unencrypted SSH binary packet. */
export type SSHPacketOptions = {
  blockSize?: number;
  maximumPacketLength?: number;
};

/** A decoded SSH payload and its consumed wire bytes. */
export type SSHPacketReadResult = {
  payload: Uint8Array;
  consumed: number;
};

/** Error raised when SSH binary packet framing is invalid. */
export class SSHPacketError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SSHPacketError";
  }
}

/** Formats one unencrypted RFC 4253 SSH binary packet. */
export function formatPacket(
  payload: Uint8Array,
  options: SSHPacketOptions & { padding?: Uint8Array } = {},
): Uint8Array {
  const { blockSize, maximumPacketLength } = normalizeOptions(options);
  const padding = options.padding ?? randomPadding(requiredPaddingLength(payload.length, blockSize));
  const packetLength = 1 + payload.length + padding.length;
  assertPacketLayout(packetLength, padding.length, blockSize, maximumPacketLength);

  const packet = new Uint8Array(4 + packetLength);
  new DataView(packet.buffer).setUint32(0, packetLength);
  packet[4] = padding.length;
  packet.set(payload, 5);
  packet.set(padding, 5 + payload.length);
  return packet;
}

/**
 * Reads one complete unencrypted RFC 4253 SSH binary packet.
 * Returns undefined when more input is required.
 */
export function readPacket(input: Uint8Array, options: SSHPacketOptions = {}): SSHPacketReadResult | undefined {
  const { blockSize, maximumPacketLength } = normalizeOptions(options);
  if (input.length < 4)
    return undefined;
  const packetLength = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(0);
  if (packetLength > maximumPacketLength)
    throw new SSHPacketError("SSH packet length exceeds the configured maximum");
  if (input.length < 4 + packetLength)
    return undefined;

  const paddingLength = input[4];
  assertPacketLayout(packetLength, paddingLength, blockSize, maximumPacketLength);
  const payloadEnd = 4 + packetLength - paddingLength;
  return { payload: input.slice(5, payloadEnd), consumed: 4 + packetLength };
}

function normalizeOptions(options: SSHPacketOptions): Required<SSHPacketOptions> {
  const blockSize = options.blockSize ?? DEFAULT_BLOCK_SIZE;
  const maximumPacketLength = options.maximumPacketLength ?? DEFAULT_MAXIMUM_PACKET_LENGTH;
  if (!Number.isSafeInteger(blockSize) || blockSize < 8)
    throw new SSHPacketError("SSH packet block size must be a safe integer of at least 8");
  if (!Number.isSafeInteger(maximumPacketLength) || maximumPacketLength < 5 || maximumPacketLength > 0xffff_ffff) {
    throw new SSHPacketError("maximum SSH packet length must be an integer between 5 and 2^32 - 1");
  }
  return { blockSize, maximumPacketLength };
}

function requiredPaddingLength(payloadLength: number, blockSize: number): number {
  let paddingLength = blockSize - ((payloadLength + 5) % blockSize);
  if (paddingLength < 4)
    paddingLength += blockSize;
  return paddingLength;
}

function assertPacketLayout(
  packetLength: number,
  paddingLength: number,
  blockSize: number,
  maximumPacketLength: number,
): void {
  if (packetLength > maximumPacketLength)
    throw new SSHPacketError("SSH packet length exceeds the configured maximum");
  if (packetLength < 5)
    throw new SSHPacketError("SSH packet length is too short");
  if ((packetLength + 4) % blockSize !== 0)
    throw new SSHPacketError("SSH packet length is not aligned to the encryption block size");
  if (paddingLength < 4 || paddingLength >= packetLength)
    throw new SSHPacketError("SSH packet padding length is invalid");
}

function randomPadding(length: number): Uint8Array {
  const padding = new Uint8Array(length);
  crypto.getRandomValues(padding);
  return padding;
}
