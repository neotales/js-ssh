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
export declare class SFTPError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Formats a complete SFTP packet from its message type and type-specific payload. */
export declare function formatSftpPacket(type: number, payload: Uint8Array): Uint8Array;
/** Reads one complete SFTP packet, returning undefined when more input is required. */
export declare function readSftpPacket(input: Uint8Array, maximumPacketLength?: number): SFTPPacket | undefined;
/** Formats SSH_FXP_INIT. */
export declare function formatSftpInit(init: SFTPInit): Uint8Array;
/** Parses SSH_FXP_INIT, preserving bytes consumed when followed by another SFTP packet. */
export declare function parseSftpInit(input: Uint8Array): (SFTPInit & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_VERSION. */
export declare function formatSftpVersion(version: SFTPVersion): Uint8Array;
/** Parses SSH_FXP_VERSION, preserving bytes consumed when followed by another SFTP packet. */
export declare function parseSftpVersion(input: Uint8Array): (SFTPVersion & {
    consumed: number;
}) | undefined;
