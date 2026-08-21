import { SSHPublicKey } from "./public_key.js";
import { SSHSignature } from "./signature.js";
/** An Ed25519 private CryptoKey and its SSH wire public key. */
export type SSHEd25519KeyPair = {
    privateKey: CryptoKey;
    publicKey: SSHPublicKey;
};
/** Generates an Ed25519 key pair suitable for SSH public-key authentication. */
export declare function generateEd25519KeyPair(): Promise<SSHEd25519KeyPair>;
/** Signs message bytes and returns the SSH wire representation of an ssh-ed25519 signature. */
export declare function signEd25519(privateKey: CryptoKey, message: Uint8Array): Promise<SSHSignature>;
