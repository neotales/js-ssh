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
export declare class SSHPacketError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Formats one unencrypted RFC 4253 SSH binary packet. */
export declare function formatPacket(payload: Uint8Array, options?: SSHPacketOptions & {
    padding?: Uint8Array;
}): Uint8Array;
/**
 * Reads one complete unencrypted RFC 4253 SSH binary packet.
 * Returns undefined when more input is required.
 */
export declare function readPacket(input: Uint8Array, options?: SSHPacketOptions): SSHPacketReadResult | undefined;
