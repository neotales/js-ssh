import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { formatChannelClose, formatChannelData, formatChannelEof, formatChannelExtendedData, formatChannelOpenConfirmation, formatChannelOpenFailure, formatChannelRequestFailure, formatChannelRequestSuccess, formatChannelWindowAdjust, formatExecChannelRequest, formatExitStatus, formatGlobalRequest, formatGlobalRequestFailure, formatGlobalRequestSuccess, formatSessionChannelOpen, formatSubsystemChannelRequest, parseChannelClose, parseChannelData, parseChannelEof, parseChannelExtendedData, parseChannelOpenConfirmation, parseChannelOpenFailure, parseChannelRequest, parseChannelRequestFailure, parseChannelRequestSuccess, parseChannelWindowAdjust, parseExecChannelRequest, parseExitStatus, parseGlobalRequest, parseGlobalRequestSuccess, parseSessionChannelOpen, parseSubsystemChannelRequest, SSHConnectionError, } from "./connection.js";
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
test("global requests preserve opaque data with exact RFC framing", () => {
    const request = { requestType: "keepalive@openssh.com", wantReply: true, data: Uint8Array.of(0, 0xff, 3) };
    const payload = formatGlobalRequest(request);
    deepStrictEqual(payload, Uint8Array.of(80, 0, 0, 0, 21, ...new TextEncoder().encode(request.requestType), 1, 0, 0xff, 3));
    deepStrictEqual(parseGlobalRequest(payload), request);
    request.data[0] = 9;
    deepStrictEqual(parseGlobalRequest(payload).data, Uint8Array.of(0, 0xff, 3));
    const parsed = parseGlobalRequest(payload);
    parsed.data[0] = 9;
    strictEqual(payload.at(-1), 3);
    const success = formatGlobalRequestSuccess(Uint8Array.of(0, 0xff, 3));
    deepStrictEqual(success, Uint8Array.of(81, 0, 0xff, 3));
    deepStrictEqual(parseGlobalRequestSuccess(success), Uint8Array.of(0, 0xff, 3));
    deepStrictEqual(formatGlobalRequestFailure(), Uint8Array.of(82));
});
test("generic request codecs validate types and distinguish opaque tails from trailing data", () => {
    const channelRequest = formatExecChannelRequest({ recipientChannel: 0x0102_0304, wantReply: true, command: "x" });
    const parsedChannelRequest = parseChannelRequest(channelRequest);
    deepStrictEqual(parsedChannelRequest, {
        recipientChannel: 0x0102_0304,
        requestType: "exec",
        wantReply: true,
        data: Uint8Array.of(0, 0, 0, 1, "x".charCodeAt(0)),
    });
    parsedChannelRequest.data[0] = 9;
    strictEqual(channelRequest[14], 0);
    deepStrictEqual(parseGlobalRequestSuccess(Uint8Array.of(81, 0, 0xff)), Uint8Array.of(0, 0xff));
    throws(() => parseGlobalRequest(Uint8Array.of(81)), SSHConnectionError);
    throws(() => parseChannelRequest(Uint8Array.of(80)), SSHConnectionError);
    throws(() => formatGlobalRequest({ requestType: "not valid", wantReply: false, data: new Uint8Array() }), SSHConnectionError);
    const invalidType = formatGlobalRequest({ requestType: "valid", wantReply: false, data: new Uint8Array() });
    invalidType[5] = 0x20;
    throws(() => parseGlobalRequest(invalidType), SSHConnectionError);
    channelRequest[9] = 0x20;
    throws(() => parseChannelRequest(channelRequest), SSHConnectionError);
    throws(() => parseChannelRequestSuccess(Uint8Array.of(99, 0, 0, 0, 1, 0)));
});
test("exec channel requests preserve commands and reject other request types", () => {
    const request = { recipientChannel: 1, wantReply: true, command: "uname -a" };
    deepStrictEqual(parseExecChannelRequest(formatExecChannelRequest(request)), request);
    const other = formatExecChannelRequest(request);
    other[9] = "x".charCodeAt(0);
    throws(() => parseExecChannelRequest(other), SSHConnectionError);
});
test("subsystem channel requests preserve valid UTF-8 names", () => {
    const request = { recipientChannel: 1, wantReply: true, subsystem: "sftp" };
    deepStrictEqual(parseSubsystemChannelRequest(formatSubsystemChannelRequest(request)), request);
    throws(() => formatSubsystemChannelRequest({ ...request, subsystem: "bad\0name" }), SSHConnectionError);
    const other = formatSubsystemChannelRequest(request);
    other[9] = "x".charCodeAt(0);
    throws(() => parseSubsystemChannelRequest(other), SSHConnectionError);
    const invalidUtf8 = formatSubsystemChannelRequest(request);
    invalidUtf8[23] = 0xff;
    throws(() => parseSubsystemChannelRequest(invalidUtf8), SSHConnectionError);
});
test("channel controls preserve window updates, stderr, request replies, and exit status", () => {
    const adjust = { recipientChannel: 1, bytesToAdd: 4096 };
    deepStrictEqual(parseChannelWindowAdjust(formatChannelWindowAdjust(adjust)), adjust);
    const stderr = { recipientChannel: 1, dataTypeCode: 1, data: new TextEncoder().encode("problem\n") };
    deepStrictEqual(parseChannelExtendedData(formatChannelExtendedData(stderr)), stderr);
    strictEqual(parseChannelRequestSuccess(formatChannelRequestSuccess(1)), 1);
    strictEqual(parseChannelRequestFailure(formatChannelRequestFailure(1)), 1);
    deepStrictEqual(formatChannelRequestFailure(1), Uint8Array.of(100, 0, 0, 0, 1));
    throws(() => parseChannelRequestFailure(formatGlobalRequestFailure()), SSHConnectionError);
    deepStrictEqual(parseExitStatus(formatExitStatus({ recipientChannel: 1, status: 127 })), {
        recipientChannel: 1,
        status: 127,
    });
    throws(() => formatChannelWindowAdjust({ recipientChannel: 1, bytesToAdd: 0 }), SSHConnectionError);
});
