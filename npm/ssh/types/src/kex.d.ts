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
export declare class SSHKexError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Parses a complete SSH_MSG_KEXINIT payload. */
export declare function parseKexInit(payload: Uint8Array): SSHKexInit;
/** Formats an SSH_MSG_KEXINIT payload. */
export declare function formatKexInit(init: SSHKexInit): Uint8Array;
