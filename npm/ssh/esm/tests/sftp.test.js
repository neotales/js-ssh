import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { formatSftpInit, formatSftpPacket, formatSftpVersion, parseSftpInit, parseSftpVersion, readSftpPacket, SFTPError, } from "../sftp.js";
test("SFTP framing reads complete packets and preserves trailing data", () => {
    const first = formatSftpPacket(200, Uint8Array.of(1, 2));
    const second = formatSftpPacket(201, Uint8Array.of(3));
    const combined = new Uint8Array(first.length + second.length);
    combined.set(first);
    combined.set(second, first.length);
    strictEqual(readSftpPacket(first.slice(0, -1)), undefined);
    const packet = readSftpPacket(combined);
    if (!packet)
        throw new Error("expected an SFTP packet");
    strictEqual(packet.type, 200);
    deepStrictEqual(packet.payload, Uint8Array.of(1, 2));
    strictEqual(packet.consumed, first.length);
});
test("SFTP init and version negotiation preserve extension data", () => {
    const init = { version: 3, extensions: [{ name: "posix-rename@openssh.com", data: Uint8Array.of(1) }] };
    const parsedInit = parseSftpInit(formatSftpInit(init));
    if (!parsedInit)
        throw new Error("expected an SFTP init packet");
    deepStrictEqual(parsedInit.extensions, init.extensions);
    strictEqual(parsedInit.version, 3);
    const version = { version: 3, extensions: [{ name: "limits@openssh.com", data: Uint8Array.of(2, 3) }] };
    const parsedVersion = parseSftpVersion(formatSftpVersion(version));
    if (!parsedVersion)
        throw new Error("expected an SFTP version packet");
    deepStrictEqual(parsedVersion.extensions, version.extensions);
    strictEqual(parsedVersion.version, 3);
    throws(() => formatSftpPacket(0, new Uint8Array()), SFTPError);
});
