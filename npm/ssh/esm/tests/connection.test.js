import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { formatChannelClose, formatChannelData, formatChannelEof, formatChannelOpenConfirmation, formatChannelOpenFailure, formatExecChannelRequest, formatSessionChannelOpen, parseChannelClose, parseChannelData, parseChannelEof, parseChannelOpenConfirmation, parseChannelOpenFailure, parseExecChannelRequest, parseSessionChannelOpen, SSHConnectionError, } from "../connection.js";
test("session channel open messages preserve flow-control parameters", () => {
    const open = { senderChannel: 1, initialWindowSize: 1024 * 1024, maximumPacketSize: 32_768 };
    deepStrictEqual(parseSessionChannelOpen(formatSessionChannelOpen(open)), open);
    const confirmation = { recipientChannel: 1, senderChannel: 2, initialWindowSize: 1024, maximumPacketSize: 4096 };
    deepStrictEqual(parseChannelOpenConfirmation(formatChannelOpenConfirmation(confirmation)), confirmation);
    throws(() => formatSessionChannelOpen({ ...open, maximumPacketSize: 0 }), SSHConnectionError);
});
test("channel failure, data, EOF, and close messages roundtrip", () => {
    const failure = { recipientChannel: 1, reasonCode: 3, description: "administratively prohibited", languageTag: "en" };
    deepStrictEqual(parseChannelOpenFailure(formatChannelOpenFailure(failure)), failure);
    const data = { recipientChannel: 1, data: Uint8Array.of(1, 2, 3) };
    deepStrictEqual(parseChannelData(formatChannelData(data)), data);
    strictEqual(parseChannelEof(formatChannelEof(1)), 1);
    strictEqual(parseChannelClose(formatChannelClose(1)), 1);
});
test("exec channel requests preserve commands and reject other request types", () => {
    const request = { recipientChannel: 1, wantReply: true, command: "uname -a" };
    deepStrictEqual(parseExecChannelRequest(formatExecChannelRequest(request)), request);
    const other = formatExecChannelRequest(request);
    other[9] = "x".charCodeAt(0);
    throws(() => parseExecChannelRequest(other), SSHConnectionError);
});
