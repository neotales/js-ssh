/** Parsed signature in the SSH wire format defined by RFC 4253 section 6.6. */
export declare class SSHSignature {
    #private;
    readonly format: string;
    constructor(wire: Uint8Array);
    /** Returns an owned copy of the algorithm-specific signature bytes. */
    get blob(): Uint8Array;
    /** Returns an owned copy of the complete SSH signature wire value. */
    marshal(): Uint8Array;
}
/** Parses a complete SSH signature wire value. */
export declare function parseSignature(wire: Uint8Array): SSHSignature;
