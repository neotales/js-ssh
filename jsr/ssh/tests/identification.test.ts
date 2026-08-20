import { deepStrictEqual, strictEqual, throws } from "node:assert/strict";
import { test } from "node:test";
import {
  formatIdentification,
  parseIdentification,
  readIdentification,
  SSHIdentificationError,
} from "../identification.ts";

test("SSH identification values parse and format canonically", () => {
  const value = parseIdentification("SSH-2.0-neotales_ssh 0.0.0-alpha.0");
  deepStrictEqual(value, {
    protocolVersion: "2.0",
    softwareVersion: "neotales_ssh",
    comments: "0.0.0-alpha.0",
  });
  strictEqual(formatIdentification(value), "SSH-2.0-neotales_ssh 0.0.0-alpha.0\r\n");
  strictEqual(formatIdentification({ protocolVersion: "1.99", softwareVersion: "legacy" }), "SSH-1.99-legacy\r\n");
});

test("SSH identification reader skips preamble lines and reports consumed bytes", () => {
  const input = new TextEncoder().encode("notice\r\nSSH-2.0-neotales_ssh\r\ntrailing");
  const result = readIdentification(input);
  if (!result)
    throw new Error("expected complete SSH identification");
  deepStrictEqual(result.identification, {
    protocolVersion: "2.0",
    softwareVersion: "neotales_ssh",
    comments: undefined,
  });
  strictEqual(result.consumed, 30);
  strictEqual(readIdentification(new TextEncoder().encode("SSH-2.0-neotales")), undefined);
});

test("SSH identification parsing enforces version, ASCII, framing, and line limits", () => {
  throws(() => parseIdentification("SSH-2.0-"), SSHIdentificationError);
  throws(() => parseIdentification("SSH-1.5-legacy"), SSHIdentificationError);
  throws(() => parseIdentification("SSH-2.0-test\tcomment"), SSHIdentificationError);
  throws(
    () => formatIdentification({ protocolVersion: "2.0", softwareVersion: "test", comments: "" }),
    SSHIdentificationError,
  );
  throws(() => readIdentification(new TextEncoder().encode("SSH-2.0-test\n")), SSHIdentificationError);
  throws(() => readIdentification(new Uint8Array(256).fill(0x78)), SSHIdentificationError);
});
