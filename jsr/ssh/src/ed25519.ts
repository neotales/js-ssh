import { SSHPublicKey } from "./public_key.ts";
import { SSHSignature } from "./signature.ts";
import { SSHWriter } from "./wire.ts";
import { SSHKeyError } from "./key_error.ts";

/** An Ed25519 private CryptoKey and its SSH wire public key. */
export type SSHEd25519KeyPair = {
  privateKey: CryptoKey;
  publicKey: SSHPublicKey;
};

/** Generates an Ed25519 key pair suitable for SSH public-key authentication. */
export async function generateEd25519KeyPair(): Promise<SSHEd25519KeyPair> {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = new SSHPublicKey(
    new SSHWriter().writeString(new TextEncoder().encode("ssh-ed25519")).writeString(rawPublicKey).toUint8Array(),
  );
  return { privateKey: pair.privateKey, publicKey };
}

/** Signs message bytes and returns the SSH wire representation of an ssh-ed25519 signature. */
export async function signEd25519(privateKey: CryptoKey, message: Uint8Array): Promise<SSHSignature> {
  if (privateKey.type !== "private" || privateKey.algorithm.name !== "Ed25519")
    throw new SSHKeyError("expected an Ed25519 private key");
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, privateKey, Uint8Array.from(message).buffer),
  );
  return new SSHSignature(
    new SSHWriter().writeString(new TextEncoder().encode("ssh-ed25519")).writeString(signature).toUint8Array(),
  );
}
