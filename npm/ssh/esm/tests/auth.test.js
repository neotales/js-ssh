import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import { formatServiceAccept, formatServiceRequest, formatUserAuthFailure, formatUserAuthNoneRequest, formatUserAuthPublicKeyRequest, formatUserAuthSuccess, parseServiceAccept, parseServiceRequest, parseUserAuthFailure, parseUserAuthNoneRequest, parseUserAuthPublicKeyRequest, parseUserAuthSuccess, SSHAuthError, } from "../auth.js";
import { parsePublicKey, parseSignature } from "../keys.js";
import { SSHWriter } from "../primitives.js";
test("SSH service negotiation preserves valid service names", () => {
    strictEqual(parseServiceRequest(formatServiceRequest("ssh-userauth")), "ssh-userauth");
    strictEqual(parseServiceAccept(formatServiceAccept("ssh-connection")), "ssh-connection");
    throws(() => formatServiceRequest("not valid"), SSHAuthError);
});
test("none user authentication preserves UTF-8 usernames and rejects other methods", () => {
    const payload = formatUserAuthNoneRequest({ username: "alicia", service: "ssh-connection" });
    deepStrictEqual(parseUserAuthNoneRequest(payload), { username: "alicia", service: "ssh-connection" });
    const otherMethod = payload.slice();
    otherMethod[otherMethod.length - 1] = "x".charCodeAt(0);
    throws(() => parseUserAuthNoneRequest(otherMethod), SSHAuthError);
});
test("SSH userauth failure and success messages roundtrip", () => {
    const failure = { methods: ["publickey", "password"], partialSuccess: false };
    deepStrictEqual(parseUserAuthFailure(formatUserAuthFailure(failure)), failure);
    parseUserAuthSuccess(formatUserAuthSuccess());
    throws(() => parseUserAuthSuccess(Uint8Array.of(52, 0)));
});
test("publickey userauth supports both probes and signed requests", () => {
    const key = parsePublicKey(new SSHWriter()
        .writeString(new TextEncoder().encode("ssh-ed25519"))
        .writeString(Uint8Array.from({ length: 32 }, (_, index) => index))
        .toUint8Array());
    const signature = parseSignature(new SSHWriter()
        .writeString(new TextEncoder().encode("ssh-ed25519"))
        .writeString(Uint8Array.from({ length: 64 }, (_, index) => index))
        .toUint8Array());
    const probe = parseUserAuthPublicKeyRequest(formatUserAuthPublicKeyRequest({ username: "alicia", service: "ssh-connection", key }));
    strictEqual(probe.signature, undefined);
    deepStrictEqual(probe.key.marshal(), key.marshal());
    const signed = parseUserAuthPublicKeyRequest(formatUserAuthPublicKeyRequest({ username: "alicia", service: "ssh-connection", key, signature }));
    deepStrictEqual(signed.signature?.marshal(), signature.marshal());
});
