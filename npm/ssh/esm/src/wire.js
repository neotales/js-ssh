const DEFAULT_MAX_STRING_LENGTH = 16 * 1024 * 1024;
const MAX_UINT32 = 0xffff_ffff;
const MAX_UINT64 = 0xffffffffffffffffn;
/** Error raised when SSH wire data is malformed or exceeds configured limits. */
export class SSHParseError extends Error {
    /** Byte offset at which parsing failed. */
    offset;
    constructor(message, offset) {
        super(`${message} at byte ${offset}`);
        this.name = "SSHParseError";
        this.offset = offset;
    }
}
/** Bounds-checked reader for the SSH data types defined by RFC 4251 section 5. */
export class SSHReader {
    #bytes;
    #view;
    #maxStringLength;
    #offset = 0;
    constructor(bytes, options = {}) {
        const maxStringLength = options.maxStringLength ?? DEFAULT_MAX_STRING_LENGTH;
        if (!Number.isSafeInteger(maxStringLength) ||
            maxStringLength < 0 ||
            maxStringLength > MAX_UINT32) {
            throw new RangeError("maxStringLength must be an integer between 0 and 2^32 - 1");
        }
        this.#bytes = bytes;
        this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        this.#maxStringLength = maxStringLength;
    }
    /** Current byte offset. */
    get offset() {
        return this.#offset;
    }
    /** Number of unread bytes. */
    get remaining() {
        return this.#bytes.length - this.#offset;
    }
    readByte() {
        this.#require(1, "truncated byte");
        return this.#bytes[this.#offset++];
    }
    readBoolean() {
        return this.readByte() !== 0;
    }
    readUint32() {
        this.#require(4, "truncated uint32");
        const value = this.#view.getUint32(this.#offset);
        this.#offset += 4;
        return value;
    }
    readUint64() {
        this.#require(8, "truncated uint64");
        const value = this.#view.getBigUint64(this.#offset);
        this.#offset += 8;
        return value;
    }
    /** Reads an SSH string and returns an owned copy. */
    readString() {
        const lengthOffset = this.#offset;
        const length = this.readUint32();
        if (length > this.#maxStringLength) {
            throw new SSHParseError(`SSH string length ${length} exceeds limit ${this.#maxStringLength}`, lengthOffset);
        }
        this.#require(length, "truncated SSH string");
        const value = this.#bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return value;
    }
    readMpint() {
        const offset = this.#offset;
        const bytes = this.readString();
        if (bytes.length === 0)
            return 0n;
        if (bytes[0] === 0) {
            if (bytes.length === 1 || (bytes[1] & 0x80) === 0) {
                throw new SSHParseError("noncanonical positive mpint", offset);
            }
        }
        else if (bytes[0] === 0xff && bytes.length > 1 && (bytes[1] & 0x80) !== 0) {
            throw new SSHParseError("noncanonical negative mpint", offset);
        }
        let value = 0n;
        for (const byte of bytes)
            value = (value << 8n) | BigInt(byte);
        if ((bytes[0] & 0x80) !== 0)
            value -= 1n << BigInt(bytes.length * 8);
        return value;
    }
    readNameList() {
        const offset = this.#offset;
        const bytes = this.readString();
        if (bytes.length === 0)
            return [];
        const names = [];
        let name = "";
        for (const byte of bytes) {
            if (byte === 0x2c) {
                if (!name)
                    throw new SSHParseError("name-list contains an empty name", offset);
                names.push(name);
                name = "";
            }
            else {
                if (byte < 0x21 || byte > 0x7e) {
                    throw new SSHParseError("name-list contains a non-ASCII name", offset);
                }
                if (name.length === 64) {
                    throw new SSHParseError("name-list contains a name longer than 64 bytes", offset);
                }
                name += String.fromCharCode(byte);
            }
        }
        if (!name)
            throw new SSHParseError("name-list contains an empty name", offset);
        names.push(name);
        return names;
    }
    /** Fails unless the input has been consumed exactly. */
    assertDone() {
        if (this.remaining !== 0) {
            throw new SSHParseError(`${this.remaining} trailing byte(s)`, this.#offset);
        }
    }
    #require(length, message) {
        if (length > this.remaining) {
            throw new SSHParseError(message, this.#offset);
        }
    }
}
/** Writer for the SSH data types defined by RFC 4251 section 5. */
export class SSHWriter {
    #bytes = new Uint8Array(256);
    #length = 0;
    /** Number of encoded bytes. */
    get length() {
        return this.#length;
    }
    writeByte(value) {
        if (!Number.isInteger(value) || value < 0 || value > 0xff) {
            throw new RangeError("byte must be an integer between 0 and 255");
        }
        this.#ensure(1);
        this.#bytes[this.#length++] = value;
        return this;
    }
    writeBoolean(value) {
        return this.writeByte(value ? 1 : 0);
    }
    writeUint32(value) {
        if (!Number.isSafeInteger(value) || value < 0 || value > MAX_UINT32) {
            throw new RangeError("uint32 must be an integer between 0 and 2^32 - 1");
        }
        this.#ensure(4);
        new DataView(this.#bytes.buffer).setUint32(this.#length, value);
        this.#length += 4;
        return this;
    }
    writeUint64(value) {
        if (value < 0n || value > MAX_UINT64) {
            throw new RangeError("uint64 must be between 0 and 2^64 - 1");
        }
        this.#ensure(8);
        new DataView(this.#bytes.buffer).setBigUint64(this.#length, value);
        this.#length += 8;
        return this;
    }
    writeString(value) {
        if (value.length > MAX_UINT32) {
            throw new RangeError("SSH string is too long");
        }
        this.writeUint32(value.length);
        this.#ensure(value.length);
        this.#bytes.set(value, this.#length);
        this.#length += value.length;
        return this;
    }
    writeMpint(value) {
        if (value === 0n) {
            return this.writeString(new Uint8Array());
        }
        if (value > 0n) {
            const bytes = unsignedBytes(value);
            if ((bytes[0] & 0x80) === 0)
                return this.writeString(bytes);
            const prefixed = new Uint8Array(bytes.length + 1);
            prefixed.set(bytes, 1);
            return this.writeString(prefixed);
        }
        let length = 1;
        while (value < -(1n << BigInt(length * 8 - 1)))
            length++;
        const encoded = (1n << BigInt(length * 8)) + value;
        const bytes = new Uint8Array(length);
        let remaining = encoded;
        for (let index = length - 1; index >= 0; index--) {
            bytes[index] = Number(remaining & 0xffn);
            remaining >>= 8n;
        }
        return this.writeString(bytes);
    }
    writeNameList(names) {
        for (const name of names) {
            validateName(name);
        }
        return this.writeString(new TextEncoder().encode(names.join(",")));
    }
    /** Returns an owned copy of the encoded bytes. */
    toUint8Array() {
        return this.#bytes.slice(0, this.#length);
    }
    #ensure(additional) {
        const required = this.#length + additional;
        if (!Number.isSafeInteger(required)) {
            throw new RangeError("encoded SSH data is too large");
        }
        if (required <= this.#bytes.length) {
            return;
        }
        let capacity = this.#bytes.length;
        while (capacity < required) {
            capacity = Math.max(capacity * 2, required);
        }
        const bytes = new Uint8Array(capacity);
        bytes.set(this.#bytes.subarray(0, this.#length));
        this.#bytes = bytes;
    }
}
function unsignedBytes(value) {
    const bytes = [];
    while (value > 0n) {
        bytes.push(Number(value & 0xffn));
        value >>= 8n;
    }
    bytes.reverse();
    return Uint8Array.from(bytes);
}
function validateName(name) {
    if (!name || name.length > 64) {
        throw new RangeError("SSH names must contain 1 to 64 bytes");
    }
    for (let index = 0; index < name.length; index++) {
        const code = name.charCodeAt(index);
        if (code < 0x21 || code > 0x7e || code === 0x2c) {
            throw new RangeError("SSH names must be printable US-ASCII without commas");
        }
    }
}
