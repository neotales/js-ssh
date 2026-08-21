import { type SSHAesCtrHmacSha256 } from "./cipher.js";
import { type SSHKexSelection } from "./kex.js";
import { SSHPublicKey } from "./public_key.js";
import { SFTPClient } from "./sftp.js";
/** An owned, portable, full-duplex SSH byte transport. */
export type SSHTransport = {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
    close?: (reason?: unknown) => void | Promise<void>;
};
/** Immutable algorithms selected for a managed SSH connection. */
export type SSHNegotiatedAlgorithms = Readonly<SSHKexSelection>;
/** Verified server identity and negotiated transport metadata passed to a host verifier. */
export type SSHHostVerificationContext = Readonly<{
    hostname: string;
    port: number;
    peerKey: SSHPublicKey;
    peerSoftwareIdentification: string;
    algorithms: SSHNegotiatedAlgorithms;
}>;
/** The required asynchronous SSH host-trust policy. */
export type SSHHostVerifier = {
    verify(context: SSHHostVerificationContext): Promise<void>;
};
/** The single Ed25519 public-key credential supported by the managed client core. */
export type SSHEd25519Credential = Readonly<{
    publicKey: SSHPublicKey;
    privateKey: CryptoKey;
}>;
/** Options for establishing a managed SSH client connection. */
export type ConnectOptions = Readonly<{
    transport: SSHTransport;
    host: Readonly<{
        hostname: string;
        port?: number;
    }>;
    username: string;
    hostVerifier: SSHHostVerifier;
    credential: SSHEd25519Credential;
    signal?: AbortSignal;
    maximumPacketLength?: number;
    softwareVersion?: string;
}>;
/** Immutable metadata for an authenticated managed SSH connection. */
export type SSHConnectionInfo = Readonly<{
    hostname: string;
    port: number;
    username: string;
    peerKey: SSHPublicKey;
    peerSoftwareIdentification: string;
    algorithms: SSHNegotiatedAlgorithms;
    authenticationMethod: "publickey";
}>;
/** Options for a bounded SSH `exec` command. */
export type RunOptions = Readonly<{
    /** Cancels the command; see {@link SshClient.run} for transport lifecycle semantics. */
    signal?: AbortSignal;
    /** Maximum combined stdout and stderr bytes retained in the result. Defaults to 1 MiB. */
    maximumOutputBytes?: number;
}>;
/** Options for opening a managed SFTP v3 subsystem. */
export type OpenSftpOptions = Readonly<{
    signal?: AbortSignal;
    maximumPacketLength?: number;
    maximumPendingRequests?: number;
}>;
/** Immutable completed output from an SSH `exec` command. */
export type CommandResult = Readonly<{
    stdout: Uint8Array;
    stderr: Uint8Array;
    exitCode: number;
}>;
/** Safe base error for managed-client failures. */
export declare class SSHClientError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Options for creating a raw TCP transport. */
export type ConnectTcpOptions = Readonly<{
    signal?: AbortSignal;
}>;
/**
 * Opens a raw TCP transport for {@link connect} where the runtime exposes native TCP.
 *
 * This adapter is asynchronous and unavailable in browsers, which do not expose raw TCP sockets.
 */
export declare function connectTcp(host: string, port?: number, options?: ConnectTcpOptions): Promise<SSHTransport>;
/** A host verifier rejection, preserving its cause without exposing peer payload bytes. */
export declare class SSHHostVerificationError extends SSHClientError {
    constructor(message?: string, options?: ErrorOptions);
}
/** The remote command ended without the complete SSH `exit-status`, EOF, and close sequence. */
export declare class SSHRemoteExitError extends SSHClientError {
    constructor(message: string, options?: ErrorOptions);
}
/**
 * An experimental authenticated SSH client.
 *
 * A client owns its transport after connecting. A private multiplexer continuously routes post-authentication
 * traffic to up to 64 managed command and SFTP channels.
 */
export declare class SshClient implements AsyncDisposable {
    #private;
    readonly connectionInfo: SSHConnectionInfo;
    private constructor();
    /** Creates an owning client after its handshake has completed. @internal */
    static create(io: ClientIo, connectionInfo: SSHConnectionInfo): SshClient;
    /** Immediately terminates the owned transport and rejects any pending command. */
    close(reason?: unknown): Promise<void>;
    /** Immediately aborts the owned transport. */
    abort(reason?: unknown): Promise<void>;
    /** Immediately starts best-effort transport termination without waiting for cleanup. */
    dispose(reason?: unknown): void;
    /** Immediately starts best-effort transport termination without waiting for cleanup. */
    [Symbol.dispose](): void;
    /** Immediately terminates the owned transport. */
    [Symbol.asyncDispose](): Promise<void>;
    /**
     * Runs one bounded remote `exec` command on an owned `session` channel.
     *
     * Commands may run concurrently, up to the managed-channel limit. The result resolves after remote EOF,
     * close, and `exit-status`; a nonzero exit status is result data. Stdout and stderr share
     * `maximumOutputBytes`, which defaults to 1 MiB. Cancelling after opening has started closes only this
     * channel and rejects this command. Calling `close()` rejects every active child operation.
     */
    run(command: string, options?: RunOptions): Promise<CommandResult>;
    /**
     * Opens one managed SFTP v3 subsystem channel.
     *
     * Commands and SFTP subsystems may coexist, up to the managed-channel limit. Closing the returned SFTP
     * client closes only its subsystem channel. Aborting after channel opening starts closes only this channel.
     */
    openSftp(options?: OpenSftpOptions): Promise<SFTPClient>;
}
/**
 * Establishes an SSH transport and authenticates with the supplied Ed25519 credential.
 *
 * The client takes ownership of `transport` only after it has acquired both stream locks.
 */
export declare function connect(options: ConnectOptions): Promise<SshClient>;
declare class ClientIo {
    #private;
    inboundCipher?: SSHAesCtrHmacSha256;
    outboundCipher?: SSHAesCtrHmacSha256;
    constructor(transport: SSHTransport, reader: ReadableStreamDefaultReader<Uint8Array>, writer: WritableStreamDefaultWriter<Uint8Array>, maximumPacketLength: number);
    get isShutdown(): boolean;
    get bytes(): Uint8Array;
    consume(length: number): void;
    readMore(): Promise<void>;
    writeBytes(bytes: Uint8Array): Promise<void>;
    writePayload(payload: Uint8Array): Promise<void>;
    readPayload(): Promise<Uint8Array>;
    shutdown(reason?: unknown): Promise<void>;
}
export {};
