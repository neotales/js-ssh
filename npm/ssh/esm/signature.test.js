import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { parseSignature, SSHKeyError } from "./keys.js";
import { SSHWriter } from "./primitives.js";
function signatureWire(format, blob) {
    return new SSHWriter().writeString(new TextEncoder().encode(format)).writeString(blob).toUint8Array();
}
test("SSH signatures preserve their wire format and blob", () => {
    const blob = Uint8Array.from({ length: 64 }, (_, index) => index);
    const wire = signatureWire("ssh-ed25519", blob);
    const signature = parseSignature(wire);
    strictEqual(signature.format, "ssh-ed25519");
    deepStrictEqual(signature.blob, blob);
    deepStrictEqual(signature.marshal(), wire);
});
test("SSH signature parsing validates supported formats", () => {
    const ecdsa = new SSHWriter().writeMpint(1n).writeMpint(2n).toUint8Array();
    deepStrictEqual(parseSignature(signatureWire("ecdsa-sha2-nistp256", ecdsa)).blob, ecdsa);
    throws(() => parseSignature(signatureWire("ssh-ed25519", new Uint8Array(63))), SSHKeyError);
    throws(() => parseSignature(signatureWire("rsa-sha2-512", new Uint8Array())), SSHKeyError);
    throws(() => parseSignature(signatureWire("ecdsa-sha2-nistp384", new SSHWriter().writeMpint(0n).writeMpint(1n).toUint8Array())), SSHKeyError);
    throws(() => parseSignature(signatureWire("ecdsa-sha2-nistp521", new SSHWriter().writeMpint(1n).toUint8Array())), SSHKeyError);
});
test("SSH signature parsing preserves unknown formats", () => {
    const wire = signatureWire("future-signature@example.test", Uint8Array.of(1, 2, 3));
    const signature = parseSignature(wire);
    strictEqual(signature.format, "future-signature@example.test");
    deepStrictEqual(signature.blob, Uint8Array.of(1, 2, 3));
});
