import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import {
  formatDebug,
  formatDisconnect,
  formatIgnore,
  formatUnimplemented,
  parseDebug,
  parseDisconnect,
  parseIgnore,
  parseUnimplemented,
  SSHTransportError,
} from "./transport.ts";

test("SSH transport disconnect and debug messages preserve diagnostics", () => {
  const disconnect = { reasonCode: 11, description: "by application", languageTag: "en" };
  deepStrictEqual(parseDisconnect(formatDisconnect(disconnect)), disconnect);
  const debug = { alwaysDisplay: false, message: "key exchange complete", languageTag: "" };
  deepStrictEqual(parseDebug(formatDebug(debug)), debug);
  throws(() => formatDebug({ ...debug, message: "bad\0message" }), SSHTransportError);
});

test("SSH transport ignore and unimplemented messages roundtrip", () => {
  deepStrictEqual(parseIgnore(formatIgnore(Uint8Array.of(1, 2, 3))), Uint8Array.of(1, 2, 3));
  strictEqual(parseUnimplemented(formatUnimplemented(42)), 42);
});
