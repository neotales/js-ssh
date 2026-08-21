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
/** SSH_FXP_OPENDIR request. */
export type SFTPOpenDirRequest = {
    id: number;
    path: string;
};
/** SSH_FXP_READDIR request. */
export type SFTPReadDirRequest = {
    id: number;
    handle: Uint8Array;
};
/** One SSH_FXP_NAME directory entry. */
export type SFTPNameEntry = {
    filename: string;
    longname: string;
    attributes: SFTPAttributes;
};
/** SSH_FXP_NAME response. */
export type SFTPName = {
    id: number;
    entries: readonly SFTPNameEntry[];
};
/** SFTP request addressing one path. */
export type SFTPPathRequest = {
    id: number;
    path: string;
};
/** SSH_FXP_MKDIR request. */
export type SFTPMkdirRequest = SFTPPathRequest & {
    attributes: SFTPAttributes;
};
/** SSH_FXP_RENAME request. */
export type SFTPRenameRequest = {
    id: number;
    oldPath: string;
    newPath: string;
};
/** SFTP request addressing an open handle. */
export type SFTPHandleRequest = {
    id: number;
    handle: Uint8Array;
};
/** SSH_FXP_SETSTAT request. */
export type SFTPSetStatRequest = SFTPPathRequest & {
    attributes: SFTPAttributes;
};
/** SSH_FXP_FSETSTAT request. */
export type SFTPFSetStatRequest = SFTPHandleRequest & {
    attributes: SFTPAttributes;
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
/** Formats SSH_FXP_WRITE. */
export declare function formatSftpWriteRequest(request: SFTPWriteRequest): Uint8Array;
/** Parses SSH_FXP_WRITE. */
export declare function parseSftpWriteRequest(input: Uint8Array): (SFTPWriteRequest & {
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
/** Formats SSH_FXP_STAT. */
export declare function formatSftpStatRequest(request: SFTPStatRequest): Uint8Array;
/** Parses SSH_FXP_STAT. */
export declare function parseSftpStatRequest(input: Uint8Array): (SFTPStatRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_OPENDIR. */
export declare function formatSftpOpenDirRequest(request: SFTPOpenDirRequest): Uint8Array;
/** Parses SSH_FXP_OPENDIR. */
export declare function parseSftpOpenDirRequest(input: Uint8Array): (SFTPOpenDirRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_READDIR. */
export declare function formatSftpReadDirRequest(request: SFTPReadDirRequest): Uint8Array;
/** Parses SSH_FXP_READDIR. */
export declare function parseSftpReadDirRequest(input: Uint8Array): (SFTPReadDirRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_NAME. */
export declare function formatSftpName(response: SFTPName): Uint8Array;
/** Parses SSH_FXP_NAME. */
export declare function parseSftpName(input: Uint8Array): (SFTPName & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_REMOVE. */
export declare function formatSftpRemoveRequest(request: SFTPPathRequest): Uint8Array;
/** Parses SSH_FXP_REMOVE. */
export declare function parseSftpRemoveRequest(input: Uint8Array): (SFTPPathRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_MKDIR. */
export declare function formatSftpMkdirRequest(request: SFTPMkdirRequest): Uint8Array;
/** Parses SSH_FXP_MKDIR. */
export declare function parseSftpMkdirRequest(input: Uint8Array): (SFTPMkdirRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_RMDIR. */
export declare function formatSftpRmdirRequest(request: SFTPPathRequest): Uint8Array;
/** Parses SSH_FXP_RMDIR. */
export declare function parseSftpRmdirRequest(input: Uint8Array): (SFTPPathRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_REALPATH. */
export declare function formatSftpRealPathRequest(request: SFTPPathRequest): Uint8Array;
/** Parses SSH_FXP_REALPATH. */
export declare function parseSftpRealPathRequest(input: Uint8Array): (SFTPPathRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_RENAME. */
export declare function formatSftpRenameRequest(request: SFTPRenameRequest): Uint8Array;
/** Parses SSH_FXP_RENAME. */
export declare function parseSftpRenameRequest(input: Uint8Array): (SFTPRenameRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_ATTRS. */
export declare function formatSftpAttributes(id: number, attributes: SFTPAttributes): Uint8Array;
/** Parses SSH_FXP_ATTRS. */
export declare function parseSftpAttributes(input: Uint8Array): ({
    id: number;
    attributes: SFTPAttributes;
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_FSTAT. */
export declare function formatSftpFStatRequest(request: SFTPHandleRequest): Uint8Array;
/** Parses SSH_FXP_FSTAT. */
export declare function parseSftpFStatRequest(input: Uint8Array): (SFTPHandleRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_SETSTAT. */
export declare function formatSftpSetStatRequest(request: SFTPSetStatRequest): Uint8Array;
/** Parses SSH_FXP_SETSTAT. */
export declare function parseSftpSetStatRequest(input: Uint8Array): (SFTPSetStatRequest & {
    consumed: number;
}) | undefined;
/** Formats SSH_FXP_FSETSTAT. */
export declare function formatSftpFSetStatRequest(request: SFTPFSetStatRequest): Uint8Array;
/** Parses SSH_FXP_FSETSTAT. */
export declare function parseSftpFSetStatRequest(input: Uint8Array): (SFTPFSetStatRequest & {
    consumed: number;
}) | undefined;
