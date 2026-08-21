import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import {
  formatServiceAccept,
  formatServiceRequest,
  formatUserAuthFailure,
  formatUserAuthNoneRequest,
  formatUserAuthSuccess,
  parseServiceAccept,
  parseServiceRequest,
  parseUserAuthFailure,
  parseUserAuthNoneRequest,
  parseUserAuthSuccess,
  SSHAuthError,
} from "../auth.ts";

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
