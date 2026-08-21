/** Error raised when SSH wire data is malformed or exceeds configured limits. */
export declare class SSHParseError extends Error {
    /** Byte offset at which parsing failed. */
    readonly offset: number;
    constructor(message: string, offset: number);
}
/** Bounds-checked reader for the SSH data types defined by RFC 4251 section 5. */
export declare class SSHReader {
    #private;
    constructor(bytes: Uint8Array, options?: {
        maxStringLength?: number;
    });
    /** Current byte offset. */
    get offset(): number;
    /** Number of unread bytes. */
    get remaining(): number;
    readByte(): number;
    readBoolean(): boolean;
    readUint32(): number;
    readUint64(): bigint;
    /** Reads an SSH string and returns an owned copy. */
    readString(): Uint8Array;
    readMpint(): bigint;
    readNameList(): string[];
    /** Fails unless the input has been consumed exactly. */
    assertDone(): void;
}
/** Writer for the SSH data types defined by RFC 4251 section 5. */
export declare class SSHWriter {
    #private;
    /** Number of encoded bytes. */
    get length(): number;
    writeByte(value: number): this;
    writeBoolean(value: boolean): this;
    writeUint32(value: number): this;
    writeUint64(value: bigint): this;
    writeString(value: Uint8Array): this;
    writeMpint(value: bigint): this;
    writeNameList(names: readonly string[]): this;
    /** Returns an owned copy of the encoded bytes. */
    toUint8Array(): Uint8Array;
}
