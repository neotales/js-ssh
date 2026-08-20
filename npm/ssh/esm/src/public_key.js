import { SSHParseError, SSHReader } from "./wire.js";
const MAX_KEY_TYPE_LENGTH = 64;
const BASE64_CHUNK_LENGTH = 0x8000;
/** Error raised when an SSH public-key value or its text encoding is malformed. */
export class SSHKeyError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHKeyError";
    }
}
/** Parsed public key in the SSH wire format defined by RFC 4253 section 6.6. */
export class SSHPublicKey {
    type;
    #wire;
    constructor(wire) {
        const reader = new SSHReader(wire);
        try {
            this.type = decodeKeyType(reader.readString());
        }
        catch (error) {
            if (error instanceof SSHParseError) {
                throw new SSHKeyError("invalid SSH public-key wire format", { cause: error });
            }
            throw error;
        }
        this.#wire = wire.slice();
    }
    /** Returns an owned copy of the complete SSH public-key wire blob. */
    marshal() {
        return this.#wire.slice();
    }
}
/** Parses an SSH public key from its complete length-prefixed wire blob. */
export function parsePublicKey(wire) {
    return new SSHPublicKey(wire);
}
/** Parses one ordinary OpenSSH authorized_keys public-key line without options or markers. */
export function parseAuthorizedKey(line) {
    const text = typeof line === "string" ? line : decodeUtf8(line);
    if (text.includes("\r") || text.includes("\n")) {
        throw new SSHKeyError("authorized-key input must contain exactly one line");
    }
    const typeEnd = readAuthorizedKeyFieldEnd(text, 0);
    if (typeEnd === 0 || typeEnd === text.length) {
        throw new SSHKeyError("invalid authorized-key line");
    }
    const encodedStart = skipHorizontalWhitespace(text, typeEnd);
    if (encodedStart === typeEnd)
        throw new SSHKeyError("invalid authorized-key line");
    const encodedEnd = readAuthorizedKeyFieldEnd(text, encodedStart);
    if (encodedEnd === encodedStart)
        throw new SSHKeyError("invalid authorized-key line");
    const commentStart = skipHorizontalWhitespace(text, encodedEnd);
    const wire = decodeBase64(text.slice(encodedStart, encodedEnd));
    const key = parsePublicKey(wire);
    if (key.type !== text.slice(0, typeEnd)) {
        throw new SSHKeyError("authorized-key type does not match its public-key blob");
    }
    return { key, comment: text.slice(commentStart) };
}
/** Formats one ordinary OpenSSH authorized_keys public-key line without options or markers. */
export function formatAuthorizedKey(key, comment = "") {
    if (comment.includes("\r") || comment.includes("\n")) {
        throw new SSHKeyError("authorized-key comments cannot contain line breaks");
    }
    return `${key.type} ${encodeBase64(key.marshal())}${comment ? ` ${comment}` : ""}\n`;
}
/** Returns the OpenSSH SHA-256 fingerprint for an SSH public-key wire blob. */
export async function fingerprintSHA256(key) {
    const wire = key.marshal();
    const input = new Uint8Array(wire.length);
    input.set(wire);
    const digest = await crypto.subtle.digest("SHA-256", input);
    return `SHA256:${removeBase64Padding(encodeBase64(new Uint8Array(digest)))}`;
}
function decodeKeyType(bytes) {
    if (bytes.length === 0 || bytes.length > MAX_KEY_TYPE_LENGTH) {
        throw new SSHKeyError("SSH public-key type must contain 1 to 64 bytes");
    }
    let type = "";
    for (const byte of bytes) {
        if (byte < 0x21 || byte > 0x7e) {
            throw new SSHKeyError("SSH public-key type must be printable US-ASCII");
        }
        type += String.fromCharCode(byte);
    }
    return type;
}
function decodeUtf8(bytes) {
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }
    catch (error) {
        throw new SSHKeyError("authorized-key input must be valid UTF-8", { cause: error });
    }
}
function decodeBase64(encoded) {
    if (!isCanonicalBase64(encoded)) {
        throw new SSHKeyError("authorized-key public-key blob is not canonical Base64");
    }
    try {
        const decoded = atob(encoded);
        const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
        if (encodeBase64(bytes) !== encoded) {
            throw new SSHKeyError("authorized-key public-key blob is not canonical Base64");
        }
        return bytes;
    }
    catch (error) {
        if (error instanceof SSHKeyError)
            throw error;
        throw new SSHKeyError("authorized-key public-key blob is not valid Base64", { cause: error });
    }
}
function encodeBase64(bytes) {
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += BASE64_CHUNK_LENGTH) {
        const chunk = bytes.subarray(offset, offset + BASE64_CHUNK_LENGTH);
        for (const byte of chunk)
            binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}
function readAuthorizedKeyFieldEnd(text, start) {
    let index = start;
    while (index < text.length) {
        const code = text.charCodeAt(index);
        if (code === 0x20 || code === 0x09)
            break;
        if (code < 0x21 || code > 0x7e) {
            throw new SSHKeyError("authorized-key fields must be printable US-ASCII");
        }
        index++;
    }
    return index;
}
function skipHorizontalWhitespace(text, start) {
    let index = start;
    while (index < text.length && (text.charCodeAt(index) === 0x20 || text.charCodeAt(index) === 0x09)) {
        index++;
    }
    return index;
}
function isCanonicalBase64(encoded) {
    if (encoded.length === 0 || encoded.length % 4 !== 0)
        return false;
    let padding = 0;
    for (let index = encoded.length - 1; index >= 0 && encoded.charCodeAt(index) === 0x3d; index--) {
        padding++;
    }
    if (padding > 2 || (padding > 0 && encoded.length - padding < 2))
        return false;
    const contentLength = encoded.length - padding;
    for (let index = 0; index < contentLength; index++) {
        const code = encoded.charCodeAt(index);
        const isLetter = (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
        const isDigit = code >= 0x30 && code <= 0x39;
        if (!isLetter && !isDigit && code !== 0x2b && code !== 0x2f)
            return false;
    }
    for (let index = contentLength; index < encoded.length; index++) {
        if (encoded.charCodeAt(index) !== 0x3d)
            return false;
    }
    return true;
}
function removeBase64Padding(encoded) {
    let end = encoded.length;
    while (end > 0 && encoded.charCodeAt(end - 1) === 0x3d)
        end--;
    return encoded.slice(0, end);
}
