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
/** Formats SSH_FXP_OPEN with no file attributes. */
export declare function formatSftpOpenRequest(request: SFTPOpenRequest): Uint8Array;
/** Parses SSH_FXP_OPEN with no file attributes. */
export declare function parseSftpOpenRequest(input: Uint8Array): (SFTPOpenRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_CLOSE. */
export declare function formatSftpCloseRequest(request: SFTPCloseRequest): Uint8Array;
/** Parses SSH_FXP_CLOSE. */
export declare function parseSftpCloseRequest(input: Uint8Array): (SFTPCloseRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_READ. */
export declare function formatSftpReadRequest(request: SFTPReadRequest): Uint8Array;
/** Parses SSH_FXP_READ. */
export declare function parseSftpReadRequest(input: Uint8Array): (SFTPReadRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_HANDLE. */
export declare function formatSftpHandle(response: SFTPHandle): Uint8Array;
/** Parses SSH_FXP_HANDLE. */
export declare function parseSftpHandle(input: Uint8Array): (SFTPHandle & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_DATA. */
export declare function formatSftpData(response: SFTPData): Uint8Array;
/** Parses SSH_FXP_DATA. */
export declare function parseSftpData(input: Uint8Array): (SFTPData & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_STATUS. */
export declare function formatSftpStatus(response: SFTPStatus): Uint8Array;
/** Parses SSH_FXP_STATUS. */
export declare function parseSftpStatus(input: Uint8Array): (SFTPStatus & {
    consumed: number;
}) | undefined;
