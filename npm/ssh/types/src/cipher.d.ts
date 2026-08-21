/** Key material for one direction of AES-CTR with HMAC-SHA-256 SSH packet protection. */
export type SSHAesCtrHmacSha256Options = {
    encryptionKey: Uint8Array;
    initialCounter: Uint8Array;
    integrityKey: Uint8Array;
    maximumPacketLength?: number;
};
/** A decrypted payload and the protected-wire bytes consumed to obtain it. */
export type SSHProtectedPacket = {
    payload: Uint8Array;
    consumed: number;
};
/** SSH transport direction used for RFC 4253 key-material labels. */
export type SSHCipherDirection = "client-to-server" | "server-to-client";
/** Error raised when an SSH protected packet is malformed or fails authentication. */
export declare class SSHCipherError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** RFC 4253 AES-CTR packet encryption with the hmac-sha2-256 profile. */
export declare class SSHAesCtrHmacSha256 {
    #private;
    private constructor();
    /** Creates a stateful cipher for one SSH packet direction. */
    static create(options: SSHAesCtrHmacSha256Options): Promise<SSHAesCtrHmacSha256>;
    /** Encrypts and authenticates one SSH payload. */
    encrypt(payload: Uint8Array): Promise<Uint8Array>;
    /**
     * Decrypts and authenticates one SSH packet.
     * Returns undefined when more protected-wire bytes are required.
     */
    read(input: Uint8Array): Promise<SSHProtectedPacket | undefined>;
}
/**
 * Derives an aes128-ctr and hmac-sha2-256 packet cipher for one SSH transport direction.
 *
 * The exchange hash must be the current KEX hash; the session ID remains the first exchange hash.
 */
export declare function createAes128CtrHmacSha256Cipher(sharedSecret: Uint8Array, exchangeHash: Uint8Array, sessionId: Uint8Array, direction: SSHCipherDirection): Promise<SSHAesCtrHmacSha256>;
