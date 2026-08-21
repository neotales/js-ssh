/**
 * SSH public-key wire formats, authorized-key text, and fingerprints.
 *
 * @module @neotales/ssh/keys
 */

export {
  type AuthorizedKey,
  fingerprintSHA256,
  formatAuthorizedKey,
  parseAuthorizedKey,
  parsePublicKey,
  SSHPublicKey,
} from "./src/public_key.ts";
export { SSHKeyError } from "./src/key_error.ts";
export { parseSignature, SSHSignature } from "./src/signature.ts";
export { generateEd25519KeyPair, signEd25519, type SSHEd25519KeyPair } from "./src/ed25519.ts";
export { verifyEd25519Signature } from "./src/verify.ts";
