/** Parsed public key in the SSH wire format defined by RFC 4253 section 6.6. */
export declare class SSHPublicKey {
    #private;
    readonly type: string;
    constructor(wire: Uint8Array);
    /** Returns an owned copy of the complete SSH public-key wire blob. */
    marshal(): Uint8Array;
}
/** Authorized-key record with its optional trailing comment. */
export type AuthorizedKey = {
    key: SSHPublicKey;
    comment: string;
};
/** Parses an SSH public key from its complete length-prefixed wire blob. */
export declare function parsePublicKey(wire: Uint8Array): SSHPublicKey;
/** Parses one ordinary OpenSSH authorized_keys public-key line without options or markers. */
export declare function parseAuthorizedKey(line: string | Uint8Array): AuthorizedKey;
/** Formats one ordinary OpenSSH authorized_keys public-key line without options or markers. */
export declare function formatAuthorizedKey(key: SSHPublicKey, comment?: string): string;
/** Returns the OpenSSH SHA-256 fingerprint for an SSH public-key wire blob. */
export declare function fingerprintSHA256(key: SSHPublicKey): Promise<string>;
