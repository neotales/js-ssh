const DEFAULT_BLOCK_SIZE = 8;
const DEFAULT_MAXIMUM_PACKET_LENGTH = 35_000;
/** Error raised when SSH binary packet framing is invalid. */
export class SSHPacketError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHPacketError";
    }
}
/** Formats one unencrypted RFC 4253 SSH binary packet. */
export function formatPacket(payload, options = {}) {
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
export function readPacket(input, options = {}) {
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
function normalizeOptions(options) {
    const blockSize = options.blockSize ?? DEFAULT_BLOCK_SIZE;
    const maximumPacketLength = options.maximumPacketLength ?? DEFAULT_MAXIMUM_PACKET_LENGTH;
    if (!Number.isSafeInteger(blockSize) || blockSize < 8)
        throw new SSHPacketError("SSH packet block size must be a safe integer of at least 8");
    if (!Number.isSafeInteger(maximumPacketLength) || maximumPacketLength < 5 || maximumPacketLength > 0xffff_ffff) {
        throw new SSHPacketError("maximum SSH packet length must be an integer between 5 and 2^32 - 1");
    }
    return { blockSize, maximumPacketLength };
}
function requiredPaddingLength(payloadLength, blockSize) {
    let paddingLength = blockSize - ((payloadLength + 5) % blockSize);
    if (paddingLength < 4)
        paddingLength += blockSize;
    return paddingLength;
}
function assertPacketLayout(packetLength, paddingLength, blockSize, maximumPacketLength) {
    if (packetLength > maximumPacketLength)
        throw new SSHPacketError("SSH packet length exceeds the configured maximum");
    if (packetLength < 5)
        throw new SSHPacketError("SSH packet length is too short");
    if ((packetLength + 4) % blockSize !== 0)
        throw new SSHPacketError("SSH packet length is not aligned to the encryption block size");
    if (paddingLength < 4 || paddingLength >= packetLength)
        throw new SSHPacketError("SSH packet padding length is invalid");
}
function randomPadding(length) {
    const padding = new Uint8Array(length);
    crypto.getRandomValues(padding);
    return padding;
}
