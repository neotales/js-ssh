import { SSHKeyError } from "./key_error.ts";
import { SSHPublicKey } from "./public_key.ts";
import { SSHSignature } from "./signature.ts";
import { SSHReader } from "./wire.ts";

/** Verifies an ssh-ed25519 SSH signature against message bytes. */
export async function verifyEd25519Signature(
  key: SSHPublicKey,
  signature: SSHSignature,
  message: Uint8Array,
): Promise<boolean> {
  if (key.type !== "ssh-ed25519")
    throw new SSHKeyError("expected an ssh-ed25519 public key");
  if (signature.format !== "ssh-ed25519")
    throw new SSHKeyError("expected an ssh-ed25519 signature");

  const reader = new SSHReader(key.marshal());
  reader.readString();
  const publicKey = reader.readString();
  reader.assertDone();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(publicKey).buffer,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "Ed25519" },
    cryptoKey,
    Uint8Array.from(signature.blob).buffer,
    Uint8Array.from(message).buffer,
  );
}
