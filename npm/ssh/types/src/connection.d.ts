/** Parameters for opening an SSH `session` channel. */
export type SSHSessionChannelOpen = {
    senderChannel: number;
    initialWindowSize: number;
    maximumPacketSize: number;
};
/** Parameters returned by SSH_MSG_CHANNEL_OPEN_CONFIRMATION. */
export type SSHChannelOpenConfirmation = {
    recipientChannel: number;
    senderChannel: number;
    initialWindowSize: number;
    maximumPacketSize: number;
};
/** Parameters returned by SSH_MSG_CHANNEL_OPEN_FAILURE. */
export type SSHChannelOpenFailure = {
    recipientChannel: number;
    reasonCode: number;
    description: string;
    languageTag: string;
};
/** SSH_MSG_CHANNEL_DATA content. */
export type SSHChannelData = {
    recipientChannel: number;
    data: Uint8Array;
};
/** SSH `exec` channel-request parameters. */
export type SSHExecChannelRequest = {
    recipientChannel: number;
    wantReply: boolean;
    command: string;
};
/** Error raised when an SSH connection-protocol message is malformed. */
export declare class SSHConnectionError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Formats SSH_MSG_CHANNEL_OPEN for a `session` channel. */
export declare function formatSessionChannelOpen(open: SSHSessionChannelOpen): Uint8Array;
/** Parses SSH_MSG_CHANNEL_OPEN for a `session` channel. */
export declare function parseSessionChannelOpen(payload: Uint8Array): SSHSessionChannelOpen;
/** Formats SSH_MSG_CHANNEL_OPEN_CONFIRMATION. */
export declare function formatChannelOpenConfirmation(confirmation: SSHChannelOpenConfirmation): Uint8Array;
/** Parses SSH_MSG_CHANNEL_OPEN_CONFIRMATION. */
export declare function parseChannelOpenConfirmation(payload: Uint8Array): SSHChannelOpenConfirmation;
/** Formats SSH_MSG_CHANNEL_OPEN_FAILURE. */
export declare function formatChannelOpenFailure(failure: SSHChannelOpenFailure): Uint8Array;
/** Parses SSH_MSG_CHANNEL_OPEN_FAILURE. */
export declare function parseChannelOpenFailure(payload: Uint8Array): SSHChannelOpenFailure;
/** Formats SSH_MSG_CHANNEL_DATA. */
export declare function formatChannelData(data: SSHChannelData): Uint8Array;
/** Parses SSH_MSG_CHANNEL_DATA. */
export declare function parseChannelData(payload: Uint8Array): SSHChannelData;
/** Formats SSH_MSG_CHANNEL_EOF. */
export declare function formatChannelEof(recipientChannel: number): Uint8Array;
/** Parses SSH_MSG_CHANNEL_EOF. */
export declare function parseChannelEof(payload: Uint8Array): number;
/** Formats SSH_MSG_CHANNEL_CLOSE. */
export declare function formatChannelClose(recipientChannel: number): Uint8Array;
/** Parses SSH_MSG_CHANNEL_CLOSE. */
export declare function parseChannelClose(payload: Uint8Array): number;
/** Formats an SSH `exec` channel request. */
export declare function formatExecChannelRequest(request: SSHExecChannelRequest): Uint8Array;
/** Parses an SSH `exec` channel request. */
export declare function parseExecChannelRequest(payload: Uint8Array): SSHExecChannelRequest;
