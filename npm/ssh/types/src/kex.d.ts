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
/** Fields carried by SSH_MSG_KEX_ECDH_REPLY. */
export type SSHKexEcdhReply = {
    hostKey: Uint8Array;
    serverPublic: Uint8Array;
    signature: Uint8Array;
};
/** An X25519 private CryptoKey and its 32-byte SSH wire public key. */
export type SSHX25519KeyPair = {
    privateKey: CryptoKey;
    publicKey: Uint8Array;
};
/** Error raised when an SSH key-exchange message is malformed. */
export declare class SSHKexError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Parses a complete SSH_MSG_KEXINIT payload. */
export declare function parseKexInit(payload: Uint8Array): SSHKexInit;
/** Parses SSH_MSG_KEX_ECDH_INIT and returns the client's encoded public key. */
export declare function parseKexEcdhInit(payload: Uint8Array): Uint8Array;
/** Formats SSH_MSG_KEX_ECDH_INIT from a client's encoded public key. */
export declare function formatKexEcdhInit(clientPublic: Uint8Array): Uint8Array;
/** Parses SSH_MSG_KEX_ECDH_REPLY. */
export declare function parseKexEcdhReply(payload: Uint8Array): SSHKexEcdhReply;
/** Formats SSH_MSG_KEX_ECDH_REPLY. */
export declare function formatKexEcdhReply(reply: SSHKexEcdhReply): Uint8Array;
/** Parses SSH_MSG_NEWKEYS. */
export declare function parseNewKeys(payload: Uint8Array): void;
/** Formats SSH_MSG_NEWKEYS. */
export declare function formatNewKeys(): Uint8Array;
/** Generates an ephemeral X25519 key pair for curve25519-sha256 key exchange. */
export declare function generateX25519KeyPair(): Promise<SSHX25519KeyPair>;
/** Derives the 32-byte X25519 shared secret from an ephemeral private key and peer public key. */
export declare function deriveX25519Secret(privateKey: CryptoKey, peerPublicKey: Uint8Array): Promise<Uint8Array>;
/** Formats an SSH_MSG_KEXINIT payload. */
export declare function formatKexInit(init: SSHKexInit): Uint8Array;
/** Selects algorithms using the client proposal's preference order. */
export declare function negotiateKexInit(client: SSHKexInit, server: SSHKexInit): SSHKexSelection;
/** Reports whether a proposal's first key-exchange and host-key choices match the negotiated result. */
export declare function isKexGuessCorrect(proposal: SSHKexInit, selection: SSHKexSelection): boolean;
