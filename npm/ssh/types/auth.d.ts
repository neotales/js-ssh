import { SSHPublicKey } from "./public_key.js";
import { SSHSignature } from "./signature.js";
/** A parsed SSH_MSG_USERAUTH_REQUEST for the `none` method. */
export type SSHUserAuthNoneRequest = {
    username: string;
    service: string;
};
/** A parsed SSH_MSG_USERAUTH_FAILURE. */
export type SSHUserAuthFailure = {
    methods: string[];
    partialSuccess: boolean;
};
/** A parsed SSH_MSG_USERAUTH_REQUEST for the `publickey` method. */
export type SSHUserAuthPublicKeyRequest = {
    username: string;
    service: string;
    key: SSHPublicKey;
    signature?: SSHSignature;
};
/** Public-key request fields included in the RFC 4252 signature transcript. */
export type SSHUserAuthPublicKeySignatureRequest = {
    username: string;
    service: string;
    key: SSHPublicKey;
};
/** Inputs needed to create a signed ssh-ed25519 userauth request. */
export type SSHEd25519UserAuthRequest = SSHUserAuthPublicKeySignatureRequest & {
    privateKey: CryptoKey;
};
/** Error raised when an SSH authentication message is malformed. */
export declare class SSHAuthError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Parses SSH_MSG_SERVICE_REQUEST. */
export declare function parseServiceRequest(payload: Uint8Array): string;
/** Formats SSH_MSG_SERVICE_REQUEST. */
export declare function formatServiceRequest(service: string): Uint8Array;
/** Parses SSH_MSG_SERVICE_ACCEPT. */
export declare function parseServiceAccept(payload: Uint8Array): string;
/** Formats SSH_MSG_SERVICE_ACCEPT. */
export declare function formatServiceAccept(service: string): Uint8Array;
/** Parses an SSH_MSG_USERAUTH_REQUEST whose method is `none`. */
export declare function parseUserAuthNoneRequest(payload: Uint8Array): SSHUserAuthNoneRequest;
/** Formats an SSH_MSG_USERAUTH_REQUEST using the `none` method. */
export declare function formatUserAuthNoneRequest(request: SSHUserAuthNoneRequest): Uint8Array;
/** Parses an SSH_MSG_USERAUTH_REQUEST whose method is `publickey`. */
export declare function parseUserAuthPublicKeyRequest(payload: Uint8Array): SSHUserAuthPublicKeyRequest;
/** Formats an SSH_MSG_USERAUTH_REQUEST using the `publickey` method. */
export declare function formatUserAuthPublicKeyRequest(request: SSHUserAuthPublicKeyRequest): Uint8Array;
/**
 * Formats the RFC 4252 section 7 public-key authentication signature transcript.
 *
 * The result is not an SSH packet; it begins with the SSH session identifier as an SSH string.
 */
export declare function formatUserAuthPublicKeySignatureData(sessionId: Uint8Array, request: SSHUserAuthPublicKeySignatureRequest): Uint8Array;
/** Creates a signed ssh-ed25519 SSH_MSG_USERAUTH_REQUEST. */
export declare function formatSignedEd25519UserAuthRequest(sessionId: Uint8Array, request: SSHEd25519UserAuthRequest): Promise<Uint8Array>;
/** Parses SSH_MSG_USERAUTH_FAILURE. */
export declare function parseUserAuthFailure(payload: Uint8Array): SSHUserAuthFailure;
/** Formats SSH_MSG_USERAUTH_FAILURE. */
export declare function formatUserAuthFailure(failure: SSHUserAuthFailure): Uint8Array;
/** Parses SSH_MSG_USERAUTH_SUCCESS. */
export declare function parseUserAuthSuccess(payload: Uint8Array): void;
/** Formats SSH_MSG_USERAUTH_SUCCESS. */
export declare function formatUserAuthSuccess(): Uint8Array;
