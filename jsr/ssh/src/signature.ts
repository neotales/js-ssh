import { SSHKeyError } from "./key_error.ts";
import { SSHParseError, SSHReader } from "./wire.ts";

const MAX_SIGNATURE_FORMAT_LENGTH = 64;

/** Parsed signature in the SSH wire format defined by RFC 4253 section 6.6. */
export class SSHSignature {
  readonly format: string;
  #blob: Uint8Array;
  #wire: Uint8Array;

  constructor(wire: Uint8Array) {
    const reader = new SSHReader(wire);
    try {
      this.format = decodeSignatureFormat(reader.readString());
      this.#blob = reader.readString();
      validateSignature(this.format, this.#blob);
      reader.assertDone();
    } catch (error) {
      if (error instanceof SSHParseError) {
        throw new SSHKeyError("invalid SSH signature wire format", { cause: error });
      }
      throw error;
    }
    this.#wire = wire.slice();
  }

  /** Returns an owned copy of the algorithm-specific signature bytes. */
  get blob(): Uint8Array {
    return this.#blob.slice();
  }

  /** Returns an owned copy of the complete SSH signature wire value. */
  marshal(): Uint8Array {
    return this.#wire.slice();
  }
}

/** Parses a complete SSH signature wire value. */
export function parseSignature(wire: Uint8Array): SSHSignature {
  return new SSHSignature(wire);
}

function decodeSignatureFormat(bytes: Uint8Array): string {
  if (bytes.length === 0 || bytes.length > MAX_SIGNATURE_FORMAT_LENGTH) {
    throw new SSHKeyError("SSH signature format must contain 1 to 64 bytes");
  }

  let format = "";
  for (const byte of bytes) {
    if (byte < 0x21 || byte > 0x7e) {
      throw new SSHKeyError("SSH signature format must be printable US-ASCII");
    }
    format += String.fromCharCode(byte);
  }
  return format;
}

function validateSignature(format: string, blob: Uint8Array): void {
  switch (format) {
    case "ssh-ed25519":
      if (blob.length !== 64) {
        throw new SSHKeyError("Ed25519 signatures must be 64 bytes");
      }
      return;
    case "ssh-rsa":
    case "rsa-sha2-256":
    case "rsa-sha2-512":
      if (blob.length === 0) {
        throw new SSHKeyError("RSA signatures cannot be empty");
      }
      return;
    case "ecdsa-sha2-nistp256":
    case "ecdsa-sha2-nistp384":
    case "ecdsa-sha2-nistp521":
      validateEcdsaSignature(blob);
      return;
    default:
      // Unknown signature formats remain usable for forwarding and future algorithms.
      return;
  }
}

function validateEcdsaSignature(blob: Uint8Array): void {
  const reader = new SSHReader(blob);
  const r = reader.readMpint();
  const s = reader.readMpint();
  if (r <= 0n || s <= 0n) {
    throw new SSHKeyError("ECDSA signature values must be positive");
  }
  reader.assertDone();
}
