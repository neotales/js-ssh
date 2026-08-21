import { formatPacket, readPacket } from "./packet.js";
import { deriveKeyMaterial } from "./kex.js";
const AES_BLOCK_SIZE = 16;
const HMAC_LENGTH = 32;
/** Error raised when an SSH protected packet is malformed or fails authentication. */
export class SSHCipherError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHCipherError";
    }
}
/** RFC 4253 AES-CTR packet encryption with the hmac-sha2-256 profile. */
export class SSHAesCtrHmacSha256 {
    #encryptionKey;
    #integrityKey;
    #maximumPacketLength;
    #counter;
    #sequence = 0;
    constructor(encryptionKey, integrityKey, counter, maximumPacketLength) {
        this.#encryptionKey = encryptionKey;
        this.#integrityKey = integrityKey;
        this.#counter = counter;
        this.#maximumPacketLength = maximumPacketLength;
    }
    /** Creates a stateful cipher for one SSH packet direction. */
    static async create(options) {
        if (![16, 24, 32].includes(options.encryptionKey.length))
            throw new SSHCipherError("AES-CTR encryption keys must contain 16, 24, or 32 bytes");
        if (options.initialCounter.length !== AES_BLOCK_SIZE)
            throw new SSHCipherError("AES-CTR initial counters must contain exactly 16 bytes");
        if (options.integrityKey.length === 0)
            throw new SSHCipherError("HMAC-SHA-256 integrity keys must not be empty");
        const maximumPacketLength = options.maximumPacketLength ?? 35_000;
        if (!Number.isSafeInteger(maximumPacketLength) || maximumPacketLength < 5 || maximumPacketLength > 0xffff_ffff) {
            throw new SSHCipherError("maximum SSH packet length must be an integer between 5 and 2^32 - 1");
        }
        const encryptionKey = await crypto.subtle.importKey("raw", Uint8Array.from(options.encryptionKey).buffer, { name: "AES-CTR" }, false, ["encrypt", "decrypt"]);
        const integrityKey = await crypto.subtle.importKey("raw", Uint8Array.from(options.integrityKey).buffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        return new SSHAesCtrHmacSha256(encryptionKey, integrityKey, options.initialCounter.slice(), maximumPacketLength);
    }
    /** Encrypts and authenticates one SSH payload. */
    async encrypt(payload) {
        const packet = formatPacket(payload, { blockSize: AES_BLOCK_SIZE, maximumPacketLength: this.#maximumPacketLength });
        const mac = await this.#mac(packet);
        const encrypted = await this.#crypt(packet);
        this.#advance(packet.length / AES_BLOCK_SIZE);
        this.#incrementSequence();
        const output = new Uint8Array(encrypted.length + mac.length);
        output.set(encrypted);
        output.set(mac, encrypted.length);
        return output;
    }
    /**
     * Decrypts and authenticates one SSH packet.
     * Returns undefined when more protected-wire bytes are required.
     */
    async read(input) {
        if (input.length < AES_BLOCK_SIZE)
            return undefined;
        const firstBlock = await this.#crypt(input.subarray(0, AES_BLOCK_SIZE));
        const packetLength = new DataView(firstBlock.buffer, firstBlock.byteOffset, firstBlock.byteLength).getUint32(0);
        if (packetLength > this.#maximumPacketLength)
            throw new SSHCipherError("SSH packet length exceeds the configured maximum");
        const encryptedLength = 4 + packetLength;
        if (encryptedLength % AES_BLOCK_SIZE !== 0)
            throw new SSHCipherError("SSH encrypted packet length is not aligned to the AES block size");
        const totalLength = encryptedLength + HMAC_LENGTH;
        if (input.length < totalLength)
            return undefined;
        const packet = await this.#crypt(input.subarray(0, encryptedLength));
        const expectedMac = await this.#mac(packet);
        const actualMac = input.slice(encryptedLength, totalLength);
        if (!timingSafeEqual(expectedMac, actualMac))
            throw new SSHCipherError("SSH packet authentication failed");
        const decoded = readPacket(packet, { blockSize: AES_BLOCK_SIZE, maximumPacketLength: this.#maximumPacketLength });
        if (!decoded)
            throw new SSHCipherError("SSH decrypted packet is incomplete");
        this.#advance(encryptedLength / AES_BLOCK_SIZE);
        this.#incrementSequence();
        return { payload: decoded.payload, consumed: totalLength };
    }
    async #crypt(input) {
        return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter: Uint8Array.from(this.#counter).buffer, length: 128 }, this.#encryptionKey, Uint8Array.from(input).buffer));
    }
    async #mac(packet) {
        const input = new Uint8Array(4 + packet.length);
        new DataView(input.buffer).setUint32(0, this.#sequence);
        input.set(packet, 4);
        return new Uint8Array(await crypto.subtle.sign("HMAC", this.#integrityKey, input.buffer));
    }
    #advance(blocks) {
        for (let block = 0; block < blocks; block++) {
            for (let index = this.#counter.length - 1; index >= 0; index--) {
                this.#counter[index] = (this.#counter[index] + 1) & 0xff;
                if (this.#counter[index] !== 0)
                    break;
            }
        }
    }
    #incrementSequence() {
        this.#sequence = (this.#sequence + 1) >>> 0;
    }
}
/**
 * Derives an aes128-ctr and hmac-sha2-256 packet cipher for one SSH transport direction.
 *
 * The exchange hash must be the current KEX hash; the session ID remains the first exchange hash.
 */
export async function createAes128CtrHmacSha256Cipher(sharedSecret, exchangeHash, sessionId, direction) {
    const labels = direction === "client-to-server" ? { iv: "A", key: "C", mac: "E" } : { iv: "B", key: "D", mac: "F" };
    const [initialCounter, encryptionKey, integrityKey] = await Promise.all([
        deriveKeyMaterial(sharedSecret, exchangeHash, sessionId, labels.iv, AES_BLOCK_SIZE),
        deriveKeyMaterial(sharedSecret, exchangeHash, sessionId, labels.key, 16),
        deriveKeyMaterial(sharedSecret, exchangeHash, sessionId, labels.mac, HMAC_LENGTH),
    ]);
    return SSHAesCtrHmacSha256.create({ initialCounter, encryptionKey, integrityKey });
}
function timingSafeEqual(left, right) {
    if (left.length !== right.length)
        return false;
    let difference = 0;
    for (let index = 0; index < left.length; index++) {
        difference |= left[index] ^ right[index];
    }
    return difference === 0;
}
