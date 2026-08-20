import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { SSHParseError, SSHReader, SSHWriter } from "../primitives.js";
test("SSHReader and SSHWriter roundtrip primitive values", () => {
    const bytes = new SSHWriter()
        .writeByte(42)
        .writeBoolean(false)
        .writeBoolean(true)
        .writeUint32(0xffff_ffff)
        .writeUint64(0xffffffffffffffffn)
        .writeString(Uint8Array.of(1, 2, 3))
        .writeNameList(["curve25519-sha256", "ssh-ed25519"])
        .toUint8Array();
    const reader = new SSHReader(bytes);
    strictEqual(reader.readByte(), 42);
    strictEqual(reader.readBoolean(), false);
    strictEqual(reader.readBoolean(), true);
    strictEqual(reader.readUint32(), 0xffff_ffff);
    strictEqual(reader.readUint64(), 0xffffffffffffffffn);
    deepStrictEqual(reader.readString(), Uint8Array.of(1, 2, 3));
    deepStrictEqual(reader.readNameList(), ["curve25519-sha256", "ssh-ed25519"]);
    reader.assertDone();
});
test("SSH boolean accepts every nonzero wire value", () => {
    strictEqual(new SSHReader(Uint8Array.of(0)).readBoolean(), false);
    strictEqual(new SSHReader(Uint8Array.of(2)).readBoolean(), true);
    strictEqual(new SSHReader(Uint8Array.of(255)).readBoolean(), true);
});
test("SSH mpint uses canonical two's-complement encoding", () => {
    const vectors = [
        [0n, []],
        [127n, [0x7f]],
        [128n, [0, 0x80]],
        [0x9a378f9b2e332a7n, [0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]],
        [-1n, [0xff]],
        [-128n, [0x80]],
        [-129n, [0xff, 0x7f]],
    ];
    for (const [value, encoded] of vectors) {
        const bytes = new SSHWriter().writeMpint(value).toUint8Array();
        deepStrictEqual(bytes.subarray(4), Uint8Array.from(encoded));
        strictEqual(new SSHReader(bytes).readMpint(), value);
    }
});
test("SSHReader rejects noncanonical mpints", () => {
    for (const bytes of [[0], [0, 0x7f], [0xff, 0x80]]) {
        const encoded = new SSHWriter().writeString(Uint8Array.from(bytes)).toUint8Array();
        throws(() => new SSHReader(encoded).readMpint(), SSHParseError);
    }
});
test("SSHReader enforces bounds, limits, and complete consumption", () => {
    throws(() => new SSHReader(Uint8Array.of(0, 0, 0)).readUint32(), SSHParseError);
    throws(() => new SSHReader(Uint8Array.of(0, 0, 0, 2, 1)).readString(), SSHParseError);
    throws(() => new SSHReader(Uint8Array.of(0, 0, 0, 2, 1, 2), { maxStringLength: 1 }).readString(), SSHParseError);
    throws(() => new SSHReader(Uint8Array.of(1)).assertDone(), SSHParseError);
});
test("SSH name-lists reject empty and non-ASCII names", () => {
    throws(() => new SSHWriter().writeNameList([""]), RangeError);
    throws(() => new SSHWriter().writeNameList(["ssh,invalid"]), RangeError);
    throws(() => new SSHWriter().writeNameList(["snowman-\u2603"]), RangeError);
    throws(() => new SSHWriter().writeNameList(["a".repeat(65)]), RangeError);
    for (const value of [
        ",ssh-ed25519",
        "ssh-ed25519,",
        "ssh-ed25519,,ssh-rsa",
        "ssh-\n",
        "a".repeat(65),
    ]) {
        const encoded = new SSHWriter().writeString(new TextEncoder().encode(value)).toUint8Array();
        throws(() => new SSHReader(encoded).readNameList(), SSHParseError);
    }
});
test("SSHWriter validates integer ranges", () => {
    throws(() => new SSHWriter().writeByte(256), RangeError);
    throws(() => new SSHWriter().writeUint32(-1), RangeError);
    throws(() => new SSHWriter().writeUint32(0x1_0000_0000), RangeError);
    throws(() => new SSHWriter().writeUint64(-1n), RangeError);
    throws(() => new SSHWriter().writeUint64(0x10000000000000000n), RangeError);
});
