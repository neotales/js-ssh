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
/** Algorithms selected from client and server SSH_MSG_KEXINIT proposals. */
export type SSHKexSelection = {
    kexAlgorithm: string;
    serverHostKeyAlgorithm: string;
    encryptionAlgorithmClientToServer: string;
    encryptionAlgorithmServerToClient: string;
    macAlgorithmClientToServer: string;
    macAlgorithmServerToClient: string;
    compressionAlgorithmClientToServer: string;
    compressionAlgorithmServerToClient: string;
    languageClientToServer?: string;
    languageServerToClient?: string;
};
/** Error raised when an SSH key-exchange message is malformed. */
export declare class SSHKexError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Parses a complete SSH_MSG_KEXINIT payload. */
export declare function parseKexInit(payload: Uint8Array): SSHKexInit;
/** Formats an SSH_MSG_KEXINIT payload. */
export declare function formatKexInit(init: SSHKexInit): Uint8Array;
/** Selects algorithms using the client proposal's preference order. */
export declare function negotiateKexInit(client: SSHKexInit, server: SSHKexInit): SSHKexSelection;
/** Reports whether a proposal's first key-exchange and host-key choices match the negotiated result. */
export declare function isKexGuessCorrect(proposal: SSHKexInit, selection: SSHKexSelection): boolean;
