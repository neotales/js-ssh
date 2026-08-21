import { SSHPublicKey } from "./public_key.js";
import { SSHSignature } from "./signature.js";
/** Verifies an ssh-ed25519 SSH signature against message bytes. */
export declare function verifyEd25519Signature(key: SSHPublicKey, signature: SSHSignature, message: Uint8Array): Promise<boolean>;
