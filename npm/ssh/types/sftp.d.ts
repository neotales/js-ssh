/** A byte-stream SSH subsystem channel suitable for SFTP. */
export type SFTPChannel = {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
    close?: (reason?: unknown) => void | Promise<void>;
};
/** SFTP server extension metadata. */
export type SFTPExtension = {
    readonly name: string;
    readonly data: Uint8Array;
};
/** SFTP v3 file metadata. */
export type SFTPAttributes = {
    readonly size?: bigint;
    readonly uid?: number;
    readonly gid?: number;
    readonly permissions?: number;
    readonly atime?: number;
    readonly mtime?: number;
    readonly extended?: readonly {
        readonly type: string;
        readonly data: Uint8Array;
    }[];
};
/** One entry returned by {@link SFTPClient.readDir}. */
export type SFTPDirectoryEntry = {
    readonly filename: string;
    readonly longname: string;
    readonly attributes: SFTPAttributes;
};
/** Options for {@link SFTPClient.connect}. */
export type SFTPConnectOptions = {
    signal?: AbortSignal;
    maximumPacketLength?: number;
    maximumPendingRequests?: number;
};
/** Options for a streaming upload. */
export type SFTPUploadOptions = {
    create?: boolean;
    truncate?: boolean;
    signal?: AbortSignal;
};
/** Options for operations that can be cancelled. */
export type SFTPOperationOptions = {
    signal?: AbortSignal;
};
/** An SFTP status response other than SSH_FX_OK. */
export declare class SFTPStatusError extends Error {
    readonly code: number;
    readonly languageTag: string;
    constructor(code: number, message: string, languageTag: string);
}
/** A promise- and Web-stream-based SFTP v3 client over an existing subsystem channel. */
export declare class SFTPClient {
    #private;
    readonly version = 3;
    private constructor();
    /** Extensions advertised by the server during version negotiation. */
    get extensions(): readonly SFTPExtension[];
    /**
     * Negotiates SFTP v3 and takes ownership of the established subsystem channel
     * once its stream locks are acquired.
     */
    static connect(channel: SFTPChannel, options?: SFTPConnectOptions): Promise<SFTPClient>;
    /** Closes the subsystem channel and rejects outstanding requests. */
    close(reason?: unknown): Promise<void>;
    /** Immediately starts best-effort subsystem termination without waiting for cleanup. */
    dispose(reason?: unknown): void;
    /** Immediately starts best-effort subsystem termination without waiting for cleanup. */
    [Symbol.dispose](): void;
    [Symbol.asyncDispose](): Promise<void>;
    /** Gets v3 attributes for a path. */
    stat(path: string, options?: SFTPOperationOptions): Promise<SFTPAttributes>;
    /**
     * Iterates directory entries, closing the server handle when iteration ends.
     * Aborting or stopping iteration early may close the client because SFTP cannot
     * cancel an in-flight request.
     */
    readDir(path: string, options?: SFTPOperationOptions): AsyncIterable<SFTPDirectoryEntry>;
    /**
     * Opens a file as a Web readable stream. Cancelling the stream closes this client
     * when necessary to retire an in-flight READ; a request already sent may still
     * have a remote side effect because SFTP has no request cancellation message.
     */
    download(path: string, options?: SFTPOperationOptions): ReadableStream<Uint8Array>;
    /**
     * Uploads bytes or a Web readable stream, writing sequentially to one open file
     * handle. Aborting may close the client to bound completion of in-flight work;
     * requests already sent may still affect the remote file.
     */
    upload(path: string, source: Uint8Array | ReadableStream<Uint8Array>, options?: SFTPUploadOptions): Promise<void>;
}
