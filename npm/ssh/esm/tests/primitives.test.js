import * as dntShim from "../_dnt.test_shims.js";
import { SSHParseError, SSHReader, SSHWriter } from "../primitives.js";
function assertEquals(actual, expected) {
    if (Object.is(actual, expected))
        return;
    if (actual instanceof Uint8Array && expected instanceof Uint8Array) {
        if (actual.length === expected.length &&
            actual.every((byte, index) => byte === expected[index])) {
            return;
        }
    }
    else if (Array.isArray(actual) && Array.isArray(expected)) {
        if (actual.length === expected.length &&
            actual.every((value, index) => value === expected[index])) {
            return;
        }
    }
    throw new Error(`Expected ${String(expected)}, received ${String(actual)}`);
}
function assertThrows(callback, constructor) {
    try {
        callback();
    }
    catch (error) {
        if (error instanceof constructor)
            return;
        throw new Error(`Expected ${constructor.name}, received ${String(error)}`, { cause: error });
    }
    throw new Error(`Expected ${constructor.name} to be thrown`);
}
dntShim.Deno.test("SSHReader and SSHWriter roundtrip primitive values", () => {
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
    assertEquals(reader.readByte(), 42);
    assertEquals(reader.readBoolean(), false);
    assertEquals(reader.readBoolean(), true);
    assertEquals(reader.readUint32(), 0xffff_ffff);
    assertEquals(reader.readUint64(), 0xffffffffffffffffn);
    assertEquals(reader.readString(), Uint8Array.of(1, 2, 3));
    assertEquals(reader.readNameList(), ["curve25519-sha256", "ssh-ed25519"]);
    reader.assertDone();
});
dntShim.Deno.test("SSH boolean accepts every nonzero wire value", () => {
    assertEquals(new SSHReader(Uint8Array.of(0)).readBoolean(), false);
    assertEquals(new SSHReader(Uint8Array.of(2)).readBoolean(), true);
    assertEquals(new SSHReader(Uint8Array.of(255)).readBoolean(), true);
});
dntShim.Deno.test("SSH mpint uses canonical two's-complement encoding", () => {
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
        assertEquals(bytes.subarray(4), Uint8Array.from(encoded));
        assertEquals(new SSHReader(bytes).readMpint(), value);
    }
});
dntShim.Deno.test("SSHReader rejects noncanonical mpints", () => {
    for (const bytes of [[0], [0, 0x7f], [0xff, 0x80]]) {
        const encoded = new SSHWriter().writeString(Uint8Array.from(bytes)).toUint8Array();
        assertThrows(() => new SSHReader(encoded).readMpint(), SSHParseError);
    }
});
dntShim.Deno.test("SSHReader enforces bounds, limits, and complete consumption", () => {
    assertThrows(() => new SSHReader(Uint8Array.of(0, 0, 0)).readUint32(), SSHParseError);
    assertThrows(() => new SSHReader(Uint8Array.of(0, 0, 0, 2, 1)).readString(), SSHParseError);
    assertThrows(() => new SSHReader(Uint8Array.of(0, 0, 0, 2, 1, 2), { maxStringLength: 1 }).readString(), SSHParseError);
    assertThrows(() => new SSHReader(Uint8Array.of(1)).assertDone(), SSHParseError);
});
dntShim.Deno.test("SSH name-lists reject empty and non-ASCII names", () => {
    assertThrows(() => new SSHWriter().writeNameList([""]), RangeError);
    assertThrows(() => new SSHWriter().writeNameList(["ssh,invalid"]), RangeError);
    assertThrows(() => new SSHWriter().writeNameList(["snowman-\u2603"]), RangeError);
    assertThrows(() => new SSHWriter().writeNameList(["a".repeat(65)]), RangeError);
    for (const value of [
        ",ssh-ed25519",
        "ssh-ed25519,",
        "ssh-ed25519,,ssh-rsa",
        "ssh-\n",
        "a".repeat(65),
    ]) {
        const encoded = new SSHWriter().writeString(new TextEncoder().encode(value)).toUint8Array();
        assertThrows(() => new SSHReader(encoded).readNameList(), SSHParseError);
    }
});
dntShim.Deno.test("SSHWriter validates integer ranges", () => {
    assertThrows(() => new SSHWriter().writeByte(256), RangeError);
    assertThrows(() => new SSHWriter().writeUint32(-1), RangeError);
    assertThrows(() => new SSHWriter().writeUint32(0x1_0000_0000), RangeError);
    assertThrows(() => new SSHWriter().writeUint64(-1n), RangeError);
    assertThrows(() => new SSHWriter().writeUint64(0x10000000000000000n), RangeError);
});
