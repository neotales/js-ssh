import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { formatSftpCloseRequest, formatSftpData, formatSftpHandle, formatSftpInit, formatSftpOpenRequest, formatSftpPacket, formatSftpReadRequest, formatSftpStatus, formatSftpVersion, parseSftpCloseRequest, parseSftpData, parseSftpHandle, parseSftpInit, parseSftpOpenRequest, parseSftpReadRequest, parseSftpStatus, parseSftpVersion, readSftpPacket, SFTPError, } from "../sftp.js";
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
test("SFTP open, close, and read requests roundtrip with responses", () => {
    const open = { id: 1, path: "/remote.txt", pflags: 1 };
    const openWire = formatSftpOpenRequest(open);
    deepStrictEqual(parseSftpOpenRequest(openWire), { ...open, consumed: openWire.length });
    const handle = Uint8Array.of(9, 8, 7);
    const closeWire = formatSftpCloseRequest({ id: 2, handle });
    deepStrictEqual(parseSftpCloseRequest(closeWire), { id: 2, handle, consumed: closeWire.length });
    const read = { id: 3, handle, offset: 123n, length: 4096 };
    const readWire = formatSftpReadRequest(read);
    deepStrictEqual(parseSftpReadRequest(readWire), { ...read, consumed: readWire.length });
    const handleWire = formatSftpHandle({ id: 1, handle });
    deepStrictEqual(parseSftpHandle(handleWire), { id: 1, handle, consumed: handleWire.length });
    const dataWire = formatSftpData({ id: 3, data: Uint8Array.of(1, 2) });
    deepStrictEqual(parseSftpData(dataWire), {
        id: 3,
        data: Uint8Array.of(1, 2),
        consumed: dataWire.length,
    });
    const statusWire = formatSftpStatus({ id: 2, code: 0, message: "ok", languageTag: "en" });
    deepStrictEqual(parseSftpStatus(statusWire), {
        id: 2,
        code: 0,
        message: "ok",
        languageTag: "en",
        consumed: statusWire.length,
    });
});
