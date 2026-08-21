import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { fingerprintSHA256, formatAuthorizedKey, generateEd25519KeyPair, parseAuthorizedKey, parsePublicKey, parseSignature, signEd25519, SSHKeyError, verifyEd25519Signature, } from "./keys.js";
import { SSHWriter } from "./primitives.js";
function ed25519Wire() {
    return new SSHWriter()
        .writeString(new TextEncoder().encode("ssh-ed25519"))
        .writeString(Uint8Array.from({ length: 32 }, (_, index) => index))
        .toUint8Array();
}
function ecdsaWire(curve, pointLength) {
    const point = Uint8Array.from({ length: pointLength }, (_, index) => (index === 0 ? 4 : index));
    return new SSHWriter()
        .writeString(new TextEncoder().encode(`ecdsa-sha2-${curve}`))
        .writeString(new TextEncoder().encode(curve))
        .writeString(point)
        .toUint8Array();
}
test("SSH public keys preserve their wire representation", () => {
    const wire = ed25519Wire();
    const key = parsePublicKey(wire);
    strictEqual(key.type, "ssh-ed25519");
    deepStrictEqual(key.marshal(), wire);
    wire[0] = 255;
    deepStrictEqual(key.marshal(), ed25519Wire());
});
test("authorized-key text roundtrips canonically", () => {
    const key = parsePublicKey(ed25519Wire());
    const line = formatAuthorizedKey(key, "person@example.test");
    const parsed = parseAuthorizedKey(line.slice(0, -1));
    strictEqual(parsed.key.type, "ssh-ed25519");
    deepStrictEqual(parsed.key.marshal(), key.marshal());
    strictEqual(parsed.comment, "person@example.test");
    strictEqual(formatAuthorizedKey(parsed.key, parsed.comment), line);
});
test("authorized-key parsing rejects ambiguous and malformed input", () => {
    const line = formatAuthorizedKey(parsePublicKey(ed25519Wire())).slice(0, -1);
    throws(() => parseAuthorizedKey(`${line}\n`), SSHKeyError);
    throws(() => parseAuthorizedKey("ssh-ed25519 AAAA= comment"), SSHKeyError);
    throws(() => parseAuthorizedKey("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIA=="), SSHKeyError);
    throws(() => formatAuthorizedKey(parsePublicKey(ed25519Wire()), "line\nbreak"), SSHKeyError);
});
test("SSH SHA-256 fingerprints use the canonical unpadded OpenSSH form", async () => {
    const fingerprint = await fingerprintSHA256(parsePublicKey(ed25519Wire()));
    strictEqual(fingerprint, "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA");
});
test("supported public-key blobs enforce algorithm-specific structure", () => {
    deepStrictEqual(parsePublicKey(ecdsaWire("nistp256", 65)).marshal(), ecdsaWire("nistp256", 65));
    deepStrictEqual(parsePublicKey(new SSHWriter().writeString(new TextEncoder().encode("ssh-rsa")).writeMpint(65537n).writeMpint(3n).toUint8Array()).marshal(), new SSHWriter().writeString(new TextEncoder().encode("ssh-rsa")).writeMpint(65537n).writeMpint(3n).toUint8Array());
    throws(() => parsePublicKey(new SSHWriter().writeString(new TextEncoder().encode("ssh-ed25519")).toUint8Array()), SSHKeyError);
    throws(() => parsePublicKey(new SSHWriter()
        .writeString(new TextEncoder().encode("ssh-ed25519"))
        .writeString(new Uint8Array(31))
        .toUint8Array()), SSHKeyError);
    throws(() => parsePublicKey(new SSHWriter().writeString(new TextEncoder().encode("ssh-rsa")).writeMpint(0n).writeMpint(3n).toUint8Array()), SSHKeyError);
    throws(() => parsePublicKey(ecdsaWire("nistp384", 65)), SSHKeyError);
});
test("ssh-ed25519 signatures verify through native WebCrypto", async () => {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const message = new TextEncoder().encode("exchange hash");
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, message));
    const key = parsePublicKey(new SSHWriter().writeString(new TextEncoder().encode("ssh-ed25519")).writeString(publicKey).toUint8Array());
    const sshSignature = parseSignature(new SSHWriter().writeString(new TextEncoder().encode("ssh-ed25519")).writeString(signature).toUint8Array());
    strictEqual(await verifyEd25519Signature(key, sshSignature, message), true);
    strictEqual(await verifyEd25519Signature(key, sshSignature, new TextEncoder().encode("different")), false);
});
test("generated SSH Ed25519 key pairs sign data in SSH wire format", async () => {
    const pair = await generateEd25519KeyPair();
    const message = new TextEncoder().encode("public key authentication");
    const signature = await signEd25519(pair.privateKey, message);
    strictEqual(signature.format, "ssh-ed25519");
    strictEqual(await verifyEd25519Signature(pair.publicKey, signature, message), true);
});
