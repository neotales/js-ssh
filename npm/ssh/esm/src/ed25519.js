import { SSHPublicKey } from "./public_key.js";
import { SSHSignature } from "./signature.js";
import { SSHWriter } from "./wire.js";
import { SSHKeyError } from "./key_error.js";
/** Generates an Ed25519 key pair suitable for SSH public-key authentication. */
export async function generateEd25519KeyPair() {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const publicKey = new SSHPublicKey(new SSHWriter().writeString(new TextEncoder().encode("ssh-ed25519")).writeString(rawPublicKey).toUint8Array());
    return { privateKey: pair.privateKey, publicKey };
}
/** Signs message bytes and returns the SSH wire representation of an ssh-ed25519 signature. */
export async function signEd25519(privateKey, message) {
    if (privateKey.type !== "private" || privateKey.algorithm.name !== "Ed25519")
        throw new SSHKeyError("expected an Ed25519 private key");
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, Uint8Array.from(message).buffer));
    return new SSHSignature(new SSHWriter().writeString(new TextEncoder().encode("ssh-ed25519")).writeString(signature).toUint8Array());
}
