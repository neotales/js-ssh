import { deepStrictEqual, rejects, strictEqual } from "node:assert/strict";
import { test } from "node:test";
import { formatSftpAttributes, formatSftpData, formatSftpHandle, formatSftpName, formatSftpStatus, formatSftpVersion, parseSftpCloseRequest, parseSftpInit, parseSftpOpenDirRequest, parseSftpOpenRequest, parseSftpReadDirRequest, parseSftpReadRequest, parseSftpStatRequest, parseSftpWriteRequest, } from "./protocol/sftp.js";
import { SFTPClient, SFTPStatusError } from "./sftp.js";
test("SFTP client reassembles fragmented v3 packets for file and directory operations", async () => {
    const server = new FakeSftpServer();
    const client = await SFTPClient.connect(server.channel);
    strictEqual(client.version, 3);
    deepStrictEqual(client.extensions, [{ name: "vendor@example.test", data: Uint8Array.of(1) }]);
    deepStrictEqual(await client.stat("/remote.txt"), { size: 4n, permissions: 0o100644, extended: undefined });
    await rejects(client.stat("/missing.txt"), (error) => error instanceof SFTPStatusError && error.code === 2);
    const entries = [];
    for await (const entry of client.readDir("/dir"))
        entries.push(entry);
    deepStrictEqual(entries, [{
            filename: "remote.txt",
            longname: "-rw-r--r-- remote.txt",
            attributes: { size: 4n, permissions: 0o100644, extended: undefined },
        }]);
    await client.upload("/uploaded.txt", new ReadableStream({
        start(controller) {
            controller.enqueue(Uint8Array.of(5, 6));
            controller.enqueue(Uint8Array.of(7));
            controller.close();
        },
    }));
    deepStrictEqual(server.files.get("/uploaded.txt"), Uint8Array.of(5, 6, 7));
    const chunks = [];
    const reader = client.download("/remote.txt").getReader();
    while (true) {
        const { done, value } = await reader.read();
        if (done)
            break;
        chunks.push(value);
    }
    deepStrictEqual(chunks, [Uint8Array.of(1, 2, 3, 4)]);
    await client.close();
});
test("SFTP client accepts an exact-limit packet fragmented one byte at a time", async () => {
    const maximumPacketLength = 4096;
    const extensionData = new Uint8Array(maximumPacketLength - 14);
    extensionData.fill(7);
    const version = formatSftpVersion({ version: 3, extensions: [{ name: "x", data: extensionData }] });
    strictEqual(version.length, maximumPacketLength + 4);
    const peer = scriptedChannel((packet) => {
        requirePacket(parseSftpInit(packet));
        for (const byte of version)
            peer.send(Uint8Array.of(byte));
    });
    const client = await SFTPClient.connect(peer.channel, { maximumPacketLength });
    strictEqual(client.extensions[0].data.length, extensionData.length);
    await client.close();
});
test("SFTP facade forwards packet limits above the raw codec default", async () => {
    const maximumPacketLength = 1024 * 1024 + 32;
    const version = formatSftpVersion({
        version: 3,
        extensions: [{ name: "x", data: new Uint8Array(maximumPacketLength - 14) }],
    });
    const peer = scriptedChannel((packet) => {
        requirePacket(parseSftpInit(packet));
        peer.send(version);
    });
    const client = await SFTPClient.connect(peer.channel, { maximumPacketLength });
    strictEqual(client.extensions[0].data.length, maximumPacketLength - 14);
    await client.close();
});
test("SFTP connect releases its readable lock when writable acquisition fails", async () => {
    const readable = new ReadableStream();
    const writable = new WritableStream();
    const writer = writable.getWriter();
    await rejects(SFTPClient.connect({ readable, writable }), TypeError);
    strictEqual(readable.locked, false);
    writer.releaseLock();
});
test("SFTP pending request limit rejects locally and permits out-of-order responses", async () => {
    const requests = [];
    const peer = scriptedChannel((packet) => {
        if (packet[4] === 1) {
            peer.send(formatSftpVersion({ version: 3, extensions: [] }));
            return;
        }
        requests.push(requirePacket(parseSftpStatRequest(packet)));
    });
    const client = await SFTPClient.connect(peer.channel, { maximumPendingRequests: 2 });
    const first = client.stat("/first");
    const second = client.stat("/second");
    await rejects(client.stat("/third"), /pending request limit/);
    strictEqual(requests.length, 2);
    peer.send(formatSftpAttributes(requests[1].id, { size: 2n }));
    peer.send(formatSftpAttributes(requests[0].id, { size: 1n }));
    deepStrictEqual(await Promise.all([first, second]), [
        { size: 1n, extended: undefined },
        { size: 2n, extended: undefined },
    ]);
    await rejects(client.stat("invalid\0path"));
    const stillOpen = client.stat("/still-open");
    peer.send(formatSftpAttributes(requests[2].id, { size: 4n }));
    deepStrictEqual(await stillOpen, { size: 4n, extended: undefined });
    await client.close();
});
test("SFTP malformed input rejects requests and releases channel resources", async () => {
    let statReceived;
    const received = new Promise((resolve) => statReceived = resolve);
    const peer = scriptedChannel((packet) => {
        if (packet[4] === 1) {
            peer.send(formatSftpVersion({ version: 3, extensions: [] }));
        }
        else {
            requirePacket(parseSftpStatRequest(packet));
            statReceived();
        }
    });
    const client = await SFTPClient.connect(peer.channel);
    const pending = client.stat("/pending");
    await received;
    peer.send(Uint8Array.of(0, 0, 0, 0));
    await rejects(pending, /message type/);
    await peer.closed;
    await Promise.resolve();
    strictEqual(peer.channel.readable.locked, false);
    strictEqual(peer.channel.writable.locked, false);
    strictEqual(peer.abortCount, 1);
});
test("SFTP upload cancels its source when the destination write fails", async () => {
    let cancelled;
    const source = new ReadableStream({
        start(controller) {
            controller.enqueue(Uint8Array.of(1, 2, 3));
        },
        cancel(reason) {
            cancelled = reason;
        },
    });
    const peer = scriptedChannel((packet) => {
        switch (packet[4]) {
            case 1:
                peer.send(formatSftpVersion({ version: 3, extensions: [] }));
                break;
            case 3: {
                const request = requirePacket(parseSftpOpenRequest(packet));
                peer.send(formatSftpHandle({ id: request.id, handle: Uint8Array.of(1) }));
                break;
            }
            case 6: {
                const request = requirePacket(parseSftpWriteRequest(packet));
                peer.send(formatSftpStatus({ id: request.id, code: 4, message: "write failed", languageTag: "en" }));
                break;
            }
            case 4: {
                const request = requirePacket(parseSftpCloseRequest(packet));
                peer.send(ok(request.id));
                break;
            }
        }
    });
    const client = await SFTPClient.connect(peer.channel);
    await rejects(client.upload("/destination", source), SFTPStatusError);
    strictEqual(cancelled instanceof SFTPStatusError, true);
    strictEqual(source.locked, false);
    await client.close();
});
test("SFTP abort does not wait for an unresponsive CLOSE", async () => {
    const controller = new AbortController();
    let readDirReceived;
    const reading = new Promise((resolve) => readDirReceived = resolve);
    let closeRequests = 0;
    const peer = scriptedChannel((packet) => {
        switch (packet[4]) {
            case 1:
                peer.send(formatSftpVersion({ version: 3, extensions: [] }));
                break;
            case 11: {
                const request = requirePacket(parseSftpOpenDirRequest(packet));
                peer.send(formatSftpHandle({ id: request.id, handle: Uint8Array.of(1) }));
                break;
            }
            case 12:
                requirePacket(parseSftpReadDirRequest(packet));
                readDirReceived();
                break;
            case 4:
                closeRequests++;
                break;
        }
    });
    const client = await SFTPClient.connect(peer.channel);
    const iterator = client.readDir("/dir", { signal: controller.signal })[Symbol.asyncIterator]();
    const next = iterator.next();
    await reading;
    controller.abort(new Error("stop"));
    await rejects(next, /stop/);
    await peer.closed;
    strictEqual(closeRequests, 0);
    strictEqual(peer.channel.readable.locked, false);
    strictEqual(peer.channel.writable.locked, false);
});
class FakeSftpServer {
    files = new Map([["/remote.txt", Uint8Array.of(1, 2, 3, 4)]]);
    channel;
    #controller;
    #nextHandle = 1;
    #handles = new Map();
    constructor() {
        this.channel = {
            readable: new ReadableStream({
                start: (controller) => this.#controller = controller,
            }),
            writable: new WritableStream({
                write: (packet) => this.#receive(packet),
                close: () => this.#controller.close(),
            }),
            close: () => this.#controller.close(),
        };
    }
    #receive(packet) {
        switch (packet[4]) {
            case 1: {
                const init = requirePacket(parseSftpInit(packet));
                strictEqual(init.version, 3);
                this.#send(formatSftpVersion({ version: 3, extensions: [{ name: "vendor@example.test", data: Uint8Array.of(1) }] }));
                return;
            }
            case 3: {
                const request = requirePacket(parseSftpOpenRequest(packet));
                const handle = this.#open(request.path, false);
                this.#send(formatSftpHandle({ id: request.id, handle: Uint8Array.of(handle) }));
                return;
            }
            case 4: {
                const request = requirePacket(parseSftpCloseRequest(packet));
                this.#handles.delete(request.handle[0]);
                this.#send(ok(request.id));
                return;
            }
            case 5: {
                const request = requirePacket(parseSftpReadRequest(packet));
                const handle = this.#handle(request.handle);
                const data = this.files.get(handle.path) ?? new Uint8Array();
                const start = Number(request.offset);
                if (start >= data.length) {
                    this.#send(eof(request.id));
                    return;
                }
                this.#send(formatSftpData({ id: request.id, data: data.slice(start, start + request.length) }));
                return;
            }
            case 6: {
                const request = requirePacket(parseSftpWriteRequest(packet));
                const handle = this.#handle(request.handle);
                const previous = this.files.get(handle.path) ?? new Uint8Array();
                const start = Number(request.offset);
                const next = new Uint8Array(Math.max(previous.length, start + request.data.length));
                next.set(previous);
                next.set(request.data, start);
                this.files.set(handle.path, next);
                this.#send(ok(request.id));
                return;
            }
            case 11: {
                const request = requirePacket(parseSftpOpenDirRequest(packet));
                const handle = this.#open(request.path, true);
                this.#send(formatSftpHandle({ id: request.id, handle: Uint8Array.of(handle) }));
                return;
            }
            case 12: {
                const request = requirePacket(parseSftpReadDirRequest(packet));
                const handle = this.#handle(request.handle);
                if (handle.readDirectory) {
                    this.#send(eof(request.id));
                    return;
                }
                handle.readDirectory = true;
                this.#send(formatSftpName({
                    id: request.id,
                    entries: [{
                            filename: "remote.txt",
                            longname: "-rw-r--r-- remote.txt",
                            attributes: { size: 4n, permissions: 0o100644 },
                        }],
                }));
                return;
            }
            case 17: {
                const request = requirePacket(parseSftpStatRequest(packet));
                const data = this.files.get(request.path);
                if (!data) {
                    this.#send(formatSftpStatus({ id: request.id, code: 2, message: "not found", languageTag: "en" }));
                    return;
                }
                this.#send(formatSftpAttributes(request.id, { size: BigInt(data.length), permissions: 0o100644 }));
                return;
            }
            default:
                throw new Error(`unexpected fake-server request type ${packet[4]}`);
        }
    }
    #open(path, directory) {
        const handle = this.#nextHandle++;
        this.#handles.set(handle, { path, directory, readDirectory: false });
        return handle;
    }
    #handle(bytes) {
        const handle = this.#handles.get(bytes[0]);
        if (!handle)
            throw new Error("unknown fake-server handle");
        return handle;
    }
    #send(packet) {
        for (let offset = 0; offset < packet.length; offset += 3)
            this.#controller.enqueue(packet.slice(offset, offset + 3));
    }
}
function scriptedChannel(onPacket) {
    let controller;
    let abortCount = 0;
    let resolveClosed;
    let isClosed = false;
    const closed = new Promise((resolve) => resolveClosed = resolve);
    const closeReadable = () => {
        if (isClosed)
            return;
        isClosed = true;
        controller.close();
        resolveClosed();
    };
    const result = {
        channel: {
            readable: new ReadableStream({
                start(value) {
                    controller = value;
                },
            }),
            writable: new WritableStream({
                write: onPacket,
                abort() {
                    abortCount++;
                },
            }),
            close: closeReadable,
        },
        send(packet) {
            controller.enqueue(packet);
        },
        closed,
        get abortCount() {
            return abortCount;
        },
    };
    return result;
}
function ok(id) {
    return formatSftpStatus({ id, code: 0, message: "", languageTag: "" });
}
function eof(id) {
    return formatSftpStatus({ id, code: 1, message: "end of file", languageTag: "en" });
}
function requirePacket(value) {
    if (!value)
        throw new Error("expected complete SFTP packet");
    return value;
}
