import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { formatSftpAttributes, formatSftpCloseRequest, formatSftpData, formatSftpFSetStatRequest, formatSftpFStatRequest, formatSftpHandle, formatSftpInit, formatSftpMkdirRequest, formatSftpName, formatSftpOpenDirRequest, formatSftpOpenRequest, formatSftpPacket, formatSftpReadDirRequest, formatSftpReadRequest, formatSftpRealPathRequest, formatSftpRemoveRequest, formatSftpRenameRequest, formatSftpRmdirRequest, formatSftpSetStatRequest, formatSftpStatRequest, formatSftpStatus, formatSftpVersion, formatSftpWriteRequest, parseSftpAttributes, parseSftpCloseRequest, parseSftpData, parseSftpFSetStatRequest, parseSftpFStatRequest, parseSftpHandle, parseSftpInit, parseSftpMkdirRequest, parseSftpName, parseSftpOpenDirRequest, parseSftpOpenRequest, parseSftpReadDirRequest, parseSftpReadRequest, parseSftpRealPathRequest, parseSftpRemoveRequest, parseSftpRenameRequest, parseSftpRmdirRequest, parseSftpSetStatRequest, parseSftpStatRequest, parseSftpStatus, parseSftpVersion, parseSftpWriteRequest, readSftpPacket, SFTPError, } from "./sftp.js";
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
    const write = { id: 4, handle, offset: 123n, data: Uint8Array.of(4, 5, 6) };
    const writeWire = formatSftpWriteRequest(write);
    deepStrictEqual(parseSftpWriteRequest(writeWire), { ...write, consumed: writeWire.length });
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
test("SFTP stat and attributes support v3 metadata fields", () => {
    const stat = { id: 5, path: "/remote.txt" };
    const statWire = formatSftpStatRequest(stat);
    deepStrictEqual(parseSftpStatRequest(statWire), { ...stat, consumed: statWire.length });
    const attributes = {
        size: 123n,
        uid: 1000,
        gid: 1000,
        permissions: 0o100644,
        atime: 1_700_000_000,
        mtime: 1_700_000_001,
        extended: [{ type: "vendor@example.test", data: Uint8Array.of(1, 2) }],
    };
    const attrsWire = formatSftpAttributes(5, attributes);
    deepStrictEqual(parseSftpAttributes(attrsWire), { id: 5, attributes, consumed: attrsWire.length });
    throws(() => formatSftpAttributes(1, { uid: 1 }), SFTPError);
});
test("SFTP directory messages preserve handles and entry attributes", () => {
    const open = { id: 6, path: "/dir" };
    const openWire = formatSftpOpenDirRequest(open);
    deepStrictEqual(parseSftpOpenDirRequest(openWire), { ...open, consumed: openWire.length });
    const read = { id: 7, handle: Uint8Array.of(1, 2) };
    const readWire = formatSftpReadDirRequest(read);
    deepStrictEqual(parseSftpReadDirRequest(readWire), { ...read, consumed: readWire.length });
    const name = {
        id: 7,
        entries: [{
                filename: "file.txt",
                longname: "-rw-r--r-- file.txt",
                attributes: { size: 4n, permissions: 0o100644 },
            }],
    };
    const nameWire = formatSftpName(name);
    deepStrictEqual(parseSftpName(nameWire), { ...name, consumed: nameWire.length });
});
test("SFTP path management messages preserve paths and attributes", () => {
    const path = { id: 8, path: "/old.txt" };
    for (const [format, parse] of [
        [formatSftpRemoveRequest, parseSftpRemoveRequest],
        [formatSftpRmdirRequest, parseSftpRmdirRequest],
        [formatSftpRealPathRequest, parseSftpRealPathRequest],
    ]) {
        const wire = format(path);
        deepStrictEqual(parse(wire), { ...path, consumed: wire.length });
    }
    const mkdir = { id: 9, path: "/new", attributes: { permissions: 0o40755 } };
    const mkdirWire = formatSftpMkdirRequest(mkdir);
    deepStrictEqual(parseSftpMkdirRequest(mkdirWire), { ...mkdir, consumed: mkdirWire.length });
    const rename = { id: 10, oldPath: "/old.txt", newPath: "/new.txt" };
    const renameWire = formatSftpRenameRequest(rename);
    deepStrictEqual(parseSftpRenameRequest(renameWire), { ...rename, consumed: renameWire.length });
});
test("SFTP handle metadata and attribute mutation messages roundtrip", () => {
    const handle = Uint8Array.of(1, 2, 3);
    const fstat = { id: 11, handle };
    const fstatWire = formatSftpFStatRequest(fstat);
    deepStrictEqual(parseSftpFStatRequest(fstatWire), { ...fstat, consumed: fstatWire.length });
    const setstat = { id: 12, path: "/file", attributes: { permissions: 0o100600 } };
    const setstatWire = formatSftpSetStatRequest(setstat);
    deepStrictEqual(parseSftpSetStatRequest(setstatWire), { ...setstat, consumed: setstatWire.length });
    const fsetstat = { id: 13, handle, attributes: { size: 50n } };
    const fsetstatWire = formatSftpFSetStatRequest(fsetstat);
    deepStrictEqual(parseSftpFSetStatRequest(fsetstatWire), { ...fsetstat, consumed: fsetstatWire.length });
});
