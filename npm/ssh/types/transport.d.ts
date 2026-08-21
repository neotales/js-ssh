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
export declare class SSHTransportError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Formats SSH_MSG_DISCONNECT. */
export declare function formatDisconnect(disconnect: SSHDisconnect): Uint8Array;
/** Parses SSH_MSG_DISCONNECT. */
export declare function parseDisconnect(payload: Uint8Array): SSHDisconnect;
/** Formats SSH_MSG_IGNORE. */
export declare function formatIgnore(data: Uint8Array): Uint8Array;
/** Parses SSH_MSG_IGNORE. */
export declare function parseIgnore(payload: Uint8Array): Uint8Array;
/** Formats SSH_MSG_UNIMPLEMENTED. */
export declare function formatUnimplemented(packetSequence: number): Uint8Array;
/** Parses SSH_MSG_UNIMPLEMENTED. */
export declare function parseUnimplemented(payload: Uint8Array): number;
/** Formats SSH_MSG_DEBUG. */
export declare function formatDebug(debug: SSHDebug): Uint8Array;
/** Parses SSH_MSG_DEBUG. */
export declare function parseDebug(payload: Uint8Array): SSHDebug;
