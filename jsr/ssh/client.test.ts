import { deepStrictEqual, rejects, strictEqual } from "node:assert/strict";
import { test } from "node:test";
import {
  formatServiceAccept,
  formatUserAuthPublicKeySignatureData,
  formatUserAuthSuccess,
  parseServiceRequest,
  parseUserAuthPublicKeyRequest,
} from "./auth.ts";
import {
  connect,
  connectTcp,
  SSHClientError,
  type SSHHostVerificationContext,
  SSHHostVerificationError,
  SSHRemoteExitError,
  type SSHTransport,
} from "./client.ts";
import { createAes128CtrHmacSha256Cipher, type SSHAesCtrHmacSha256 } from "./cipher.ts";
import {
  formatChannelClose,
  formatChannelData,
  formatChannelEof,
  formatChannelExtendedData,
  formatChannelOpenConfirmation,
  formatChannelRequestSuccess,
  formatChannelWindowAdjust,
  formatExitStatus,
  parseChannelClose,
  parseChannelData,
  parseChannelEof,
  parseChannelWindowAdjust,
  parseExecChannelRequest,
  parseSessionChannelOpen,
  parseSubsystemChannelRequest,
} from "./connection.ts";
import {
  computeCurve25519Sha256ExchangeHash,
  deriveX25519Secret,
  formatKexEcdhReply,
  formatKexInit,
  formatNewKeys,
  generateX25519KeyPair,
  parseKexEcdhInit,
  parseKexInit,
  parseNewKeys,
} from "./kex.ts";
import { generateEd25519KeyPair, signEd25519, verifyEd25519Signature } from "./keys.ts";
import { formatPacket, readPacket } from "./packet.ts";
import {
  formatSftpAttributes,
  formatSftpVersion,
  parseSftpInit,
  parseSftpStatRequest,
  readSftpPacket,
} from "./protocol/sftp.ts";
import { formatIgnore } from "./transport.ts";

test("managed client completes encrypted Ed25519 authentication and reports verified metadata", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  void serve(peer.server, hostKey, clientKey.publicKey).catch(() => undefined);
  let context: SSHHostVerificationContext | undefined;
  const client = await connect({
    transport: peer.transport,
    host: { hostname: "ssh.example.test", port: 2222 },
    username: "alicia",
    credential: clientKey,
    hostVerifier: {
      verify(value) {
        context = value;
        return Promise.resolve();
      },
    },
  });
  if (!context)
    throw new Error("expected host verification context");
  strictEqual(context.hostname, "ssh.example.test");
  strictEqual(context.port, 2222);
  strictEqual(context.peerSoftwareIdentification, "SSH-2.0-fake-server");
  deepStrictEqual(context.peerKey.marshal(), hostKey.publicKey.marshal());
  strictEqual(context.algorithms.encryptionAlgorithmClientToServer, "aes128-ctr");
  strictEqual(Object.isFrozen(context.algorithms), true);
  strictEqual(client.connectionInfo.authenticationMethod, "publickey");
  strictEqual(Object.isFrozen(client.connectionInfo), true);
  await client.close();
  strictEqual(peer.transport.readable.locked, false);
  strictEqual(peer.transport.writable.locked, false);
  strictEqual(peer.closeCalls, 1);
});

test("host verifier rejection terminates and releases the owned transport", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  void serve(peer.server, hostKey, clientKey.publicKey).catch(() => undefined);
  await rejects(
    () =>
      connect({
        transport: peer.transport,
        host: { hostname: "ssh.example.test" },
        username: "alicia",
        credential: clientKey,
        hostVerifier: {
          verify: async () => {
            throw new Error("not trusted");
          },
        },
      }),
    SSHHostVerificationError,
  );
  strictEqual(peer.transport.readable.locked, false);
  strictEqual(peer.transport.writable.locked, false);
  strictEqual(peer.closeCalls, 1);
});

test("a bad host signature fails before host verification", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  void serve(peer.server, hostKey, clientKey.publicKey, true).catch(() => undefined);
  let verified = false;
  await rejects(
    () =>
      connect({
        transport: peer.transport,
        host: { hostname: "ssh.example.test" },
        username: "alicia",
        credential: clientKey,
        hostVerifier: {
          verify: async () => {
            verified = true;
          },
        },
      }),
    SSHClientError,
  );
  strictEqual(verified, false);
  strictEqual(peer.transport.readable.locked, false);
  strictEqual(peer.transport.writable.locked, false);
});

test("cancellation and peer EOF terminate and release transport locks", async () => {
  const clientKey = await generateEd25519KeyPair();
  const controller = new AbortController();
  const stalled = trackedTransport();
  const connecting = connect({
    transport: stalled.transport,
    host: { hostname: "ssh.example.test" },
    username: "alicia",
    credential: clientKey,
    hostVerifier: { verify: async () => undefined },
    signal: controller.signal,
  });
  controller.abort(new Error("cancelled"));
  await rejects(() => connecting, SSHClientError);
  strictEqual(stalled.transport.readable.locked, false);
  strictEqual(stalled.transport.writable.locked, false);
  strictEqual(stalled.closeCalls, 1);

  const eof = trackedTransport(true);
  await rejects(
    () =>
      connect({
        transport: eof.transport,
        host: { hostname: "ssh.example.test" },
        username: "alicia",
        credential: clientKey,
        hostVerifier: { verify: async () => undefined },
      }),
    SSHClientError,
  );
  strictEqual(eof.transport.readable.locked, false);
  strictEqual(eof.transport.writable.locked, false);
  strictEqual(eof.closeCalls, 1);
});

test("managed client retains coalesced unencrypted and encrypted packets", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  void serve(peer.server, hostKey, clientKey.publicKey, false, { coalescePackets: true }).catch(() => undefined);
  const client = await connect({
    transport: peer.transport,
    host: { hostname: "ssh.example.test" },
    username: "alicia",
    credential: clientKey,
    hostVerifier: { verify: async () => undefined },
  });
  await client.close();
  strictEqual(peer.closeCalls, 1);
});

test("managed client runs a command with fragmented and coalesced stdout and stderr", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const channel = await openExec(wire, "printf command-output");
      await writeFragmentedPayloads(
        wire,
        formatChannelData({ recipientChannel: channel.local, data: new TextEncoder().encode("first ") }),
        formatChannelExtendedData({
          recipientChannel: channel.local,
          dataTypeCode: 1,
          data: new TextEncoder().encode("warn"),
        }),
        formatChannelData({ recipientChannel: channel.local, data: new TextEncoder().encode("second") }),
        formatExitStatus({ recipientChannel: channel.local, status: 0 }),
        formatChannelEof(channel.local),
        formatChannelClose(channel.local),
      );
      await expectWindowAdjustments(wire, channel.remote, 3);
      strictEqual(parseChannelClose(await wire.readPayload()), channel.remote);
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  const result = await client.run("printf command-output");
  deepStrictEqual(result.stdout, new TextEncoder().encode("first second"));
  deepStrictEqual(result.stderr, new TextEncoder().encode("warn"));
  strictEqual(result.exitCode, 0);
  strictEqual(Object.isFrozen(result), true);
  await server;
  await client.close();
});

test("managed client returns nonzero command status as result data", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const channel = await openExec(wire, "false");
      await writeFragmentedPayloads(
        wire,
        formatExitStatus({ recipientChannel: channel.local, status: 23 }),
        formatChannelEof(channel.local),
        formatChannelClose(channel.local),
      );
      strictEqual(parseChannelClose(await wire.readPayload()), channel.remote);
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  const result = await client.run("false");
  strictEqual(result.exitCode, 23);
  deepStrictEqual(result.stdout, new Uint8Array());
  deepStrictEqual(result.stderr, new Uint8Array());
  await server;
  await client.close();
});

test("command output limit closes only the affected channel", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const channel = await openExec(wire, "large-output");
      await wire.writePayload(formatChannelData({ recipientChannel: channel.local, data: new Uint8Array(8) }));
      await expectWindowAdjustments(wire, channel.remote, 1);
      await wire.writePayload(formatChannelData({ recipientChannel: channel.local, data: new Uint8Array(1) }));
      strictEqual(parseChannelClose(await wire.readPayload()), channel.remote);
      await wire.writePayload(formatChannelClose(channel.local));
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  await rejects(() => client.run("large-output", { maximumOutputBytes: 8 }), SSHClientError);
  await server;
  strictEqual(peer.transport.readable.locked, true);
  await client.close();
  strictEqual(peer.transport.readable.locked, false);
});

test("managed client reports a missing remote exit status", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const channel = await openExec(wire, "no-status");
      await writeFragmentedPayloads(wire, formatChannelEof(channel.local), formatChannelClose(channel.local));
      strictEqual(parseChannelClose(await wire.readPayload()), channel.remote);
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  await rejects(() => client.run("no-status"), SSHRemoteExitError);
  await server;
  await client.close();
  strictEqual(peer.closeCalls, 1);
});

test("cancelling an active command closes only its channel", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  let commandStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    commandStarted = resolve;
  });
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const channel = await openExec(wire, "wait-forever");
      commandStarted();
      strictEqual(parseChannelClose(await wire.readPayload()), channel.remote);
      await wire.writePayload(formatChannelClose(channel.local));
    },
  });
  void server.catch(() => undefined);
  const client = await connectClient(peer.transport, clientKey);
  const controller = new AbortController();
  const running = client.run("wait-forever", { signal: controller.signal });
  await started;
  controller.abort(new Error("cancelled"));
  await rejects(() => running, SSHClientError);
  strictEqual(peer.transport.readable.locked, true);
  await server;
  await client.close();
  strictEqual(peer.transport.readable.locked, false);
});

test("managed client multiplexes two commands with interleaved encrypted responses", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const first = parseSessionChannelOpen(await wire.readPayload());
      const second = parseSessionChannelOpen(await wire.readPayload());
      await wire.writePayload(formatChannelOpenConfirmation({
        recipientChannel: first.senderChannel,
        senderChannel: 41,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
      }));
      await wire.writePayload(formatChannelOpenConfirmation({
        recipientChannel: second.senderChannel,
        senderChannel: 42,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
      }));
      const firstRequest = parseExecChannelRequest(await wire.readPayload());
      const secondRequest = parseExecChannelRequest(await wire.readPayload());
      const requests = new Map([[firstRequest.recipientChannel, firstRequest.command], [
        secondRequest.recipientChannel,
        secondRequest.command,
      ]]);
      strictEqual(requests.get(41), "first");
      strictEqual(requests.get(42), "second");
      await wire.writePayload(formatChannelRequestSuccess(second.senderChannel));
      await wire.writePayload(formatChannelRequestSuccess(first.senderChannel));
      const eofs = new Set([parseChannelEof(await wire.readPayload()), parseChannelEof(await wire.readPayload())]);
      deepStrictEqual(eofs, new Set([41, 42]));
      await writeFragmentedPayloads(
        wire,
        formatExitStatus({ recipientChannel: second.senderChannel, status: 2 }),
        formatChannelEof(second.senderChannel),
        formatChannelClose(second.senderChannel),
        formatExitStatus({ recipientChannel: first.senderChannel, status: 1 }),
        formatChannelEof(first.senderChannel),
        formatChannelClose(first.senderChannel),
      );
      const closes = new Set<number>();
      while (closes.size < 2) {
        const payload = await wire.readPayload();
        if (payload[0] === 96)
          continue;
        closes.add(parseChannelClose(payload));
      }
      deepStrictEqual(closes, new Set([41, 42]));
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  const [first, second] = await Promise.all([client.run("first"), client.run("second")]);
  deepStrictEqual(first.stdout, new Uint8Array());
  strictEqual(first.exitCode, 1);
  deepStrictEqual(second.stdout, new Uint8Array());
  strictEqual(second.exitCode, 2);
  await server;
  await client.close();
});

test("cancelling one multiplexed command does not close another", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  let commandsStarted!: () => void;
  const started = new Promise<void>((resolve) => commandsStarted = resolve);
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const first = parseSessionChannelOpen(await wire.readPayload());
      const second = parseSessionChannelOpen(await wire.readPayload());
      await wire.writePayload(formatChannelOpenConfirmation({
        recipientChannel: first.senderChannel,
        senderChannel: 61,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
      }));
      await wire.writePayload(formatChannelOpenConfirmation({
        recipientChannel: second.senderChannel,
        senderChannel: 62,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
      }));
      parseExecChannelRequest(await wire.readPayload());
      parseExecChannelRequest(await wire.readPayload());
      await wire.writePayload(formatChannelRequestSuccess(first.senderChannel));
      await wire.writePayload(formatChannelRequestSuccess(second.senderChannel));
      parseChannelEof(await wire.readPayload());
      parseChannelEof(await wire.readPayload());
      commandsStarted();
      strictEqual(parseChannelClose(await wire.readPayload()), 61);
      await wire.writePayload(formatChannelClose(first.senderChannel));
      await writeFragmentedPayloads(
        wire,
        formatChannelData({ recipientChannel: second.senderChannel, data: new TextEncoder().encode("still-running") }),
        formatExitStatus({ recipientChannel: second.senderChannel, status: 0 }),
        formatChannelEof(second.senderChannel),
        formatChannelClose(second.senderChannel),
      );
      while (true) {
        const payload = await wire.readPayload();
        if (payload[0] === 93)
          continue;
        strictEqual(parseChannelClose(payload), 62);
        break;
      }
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  const controller = new AbortController();
  const cancelled = client.run("cancel-me", { signal: controller.signal });
  const completed = client.run("complete-me");
  await started;
  controller.abort(new Error("cancelled"));
  await rejects(() => cancelled, SSHClientError);
  const result = await completed;
  deepStrictEqual(result.stdout, new TextEncoder().encode("still-running"));
  await server;
  strictEqual(peer.transport.readable.locked, true);
  await client.close();
});

test("managed client rejects unknown channel and unsolicited global replies as connection-fatal", async () => {
  for (const payload of [formatChannelData({ recipientChannel: 99, data: Uint8Array.of(1) }), Uint8Array.of(81)]) {
    const clientKey = await generateEd25519KeyPair();
    const hostKey = await generateEd25519KeyPair();
    const peer = createPeer();
    const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
      onAuthenticated: (wire) => wire.writePayload(payload),
    });
    const client = await connectClient(peer.transport, clientKey);
    await rejects(() => client.run("never-runs"), SSHClientError);
    await server;
    await client.close();
    strictEqual(peer.transport.readable.locked, false);
  }
});

test("managed client bounds opening and closing channels to 64", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  let openingsRead!: () => void;
  const openings = new Promise<void>((resolve) => openingsRead = resolve);
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      for (let index = 0; index < 64; index++)
        parseSessionChannelOpen(await wire.readPayload());
      openingsRead();
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  const pending = Array.from({ length: 64 }, (_, index) => client.run(`wait-${index}`));
  await openings;
  await rejects(() => client.run("over-limit"), SSHClientError);
  await client.close();
  await Promise.all(pending.map((command) => rejects(() => command, SSHClientError)));
  await server;
});

test("managed client opens an encrypted SFTP subsystem with fragmented channel data", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const channel = await openSftp(wire, 8, 8);
      const initFirst = await readSftpChannelData(wire, channel.remote);
      strictEqual(initFirst.length, 8);
      await wire.writePayload(formatChannelWindowAdjust({ recipientChannel: channel.local, bytesToAdd: 1 }));
      const initSecond = await readSftpChannelData(wire, channel.remote);
      strictEqual(requireSftpPacket(parseSftpInit(joinBytes(initFirst, initSecond))).version, 3);
      await wire.writePayload(formatChannelWindowAdjust({ recipientChannel: channel.local, bytesToAdd: 1024 }));
      const version = formatSftpVersion({ version: 3, extensions: [] });
      await writeFragmentedPayloads(
        wire,
        formatChannelData({ recipientChannel: channel.local, data: version.subarray(0, 3) }),
        formatChannelData({ recipientChannel: channel.local, data: version.subarray(3) }),
      );
      const stat = requireSftpPacket(parseSftpStatRequest(await readSftpChannelPacket(wire, channel.remote)));
      strictEqual(stat.path, "/remote.txt");
      await writeFragmentedPayloads(
        wire,
        formatChannelData({ recipientChannel: channel.local, data: formatSftpAttributes(stat.id, { size: 4n }) }),
      );
      await closeSftpChannel(wire, channel);
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  const sftp = await client.openSftp();
  deepStrictEqual(await sftp.stat("/remote.txt"), { size: 4n, extended: undefined });
  await sftp.close();
  await server;
  await client.close();
});

test("closing managed SFTP releases its lease for a later command", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const channel = await openSftp(wire);
      requireSftpPacket(parseSftpInit(await readSftpChannelPacket(wire, channel.remote)));
      await wire.writePayload(
        formatChannelData({ recipientChannel: channel.local, data: formatSftpVersion({ version: 3, extensions: [] }) }),
      );
      await closeSftpChannel(wire, channel);
      const command = await openExec(wire, "true");
      await writeFragmentedPayloads(
        wire,
        formatExitStatus({ recipientChannel: command.local, status: 0 }),
        formatChannelEof(command.local),
        formatChannelClose(command.local),
      );
      strictEqual(parseChannelClose(await wire.readPayload()), command.remote);
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  const sftp = await client.openSftp();
  await sftp.close();
  strictEqual((await client.run("true")).exitCode, 0);
  await server;
  await client.close();
});

test("managed client runs a command while an SFTP subsystem is active", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const command = parseSessionChannelOpen(await wire.readPayload());
      const sftp = parseSessionChannelOpen(await wire.readPayload());
      await wire.writePayload(formatChannelOpenConfirmation({
        recipientChannel: command.senderChannel,
        senderChannel: 51,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
      }));
      await wire.writePayload(formatChannelOpenConfirmation({
        recipientChannel: sftp.senderChannel,
        senderChannel: 52,
        initialWindowSize: 65_536,
        maximumPacketSize: 32_768,
      }));
      const commandRequest = parseExecChannelRequest(await wire.readPayload());
      const sftpRequest = parseSubsystemChannelRequest(await wire.readPayload());
      strictEqual(commandRequest.recipientChannel, 51);
      strictEqual(sftpRequest.recipientChannel, 52);
      await wire.writePayload(formatChannelRequestSuccess(command.senderChannel));
      await wire.writePayload(formatChannelRequestSuccess(sftp.senderChannel));
      strictEqual(parseChannelEof(await wire.readPayload()), 51);
      requireSftpPacket(parseSftpInit(await readSftpChannelPacket(wire, 52)));
      await writeFragmentedPayloads(
        wire,
        formatChannelData({
          recipientChannel: sftp.senderChannel,
          data: formatSftpVersion({ version: 3, extensions: [] }),
        }),
      );
      await writeFragmentedPayloads(
        wire,
        formatExitStatus({ recipientChannel: command.senderChannel, status: 0 }),
        formatChannelEof(command.senderChannel),
        formatChannelClose(command.senderChannel),
      );
      while (true) {
        const payload = await wire.readPayload();
        if (payload[0] === 93)
          continue;
        strictEqual(parseChannelClose(payload), 51);
        break;
      }
      await closeSftpChannel(wire, { local: sftp.senderChannel, remote: 52 });
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  const running = client.run("first");
  const sftp = client.openSftp();
  strictEqual((await running).exitCode, 0);
  await (await sftp).close();
  await server;
  await client.close();
});

test("an unexpected SFTP channel close terminates the parent client", async () => {
  const clientKey = await generateEd25519KeyPair();
  const hostKey = await generateEd25519KeyPair();
  const peer = createPeer();
  const server = serve(peer.server, hostKey, clientKey.publicKey, false, {
    onAuthenticated: async (wire) => {
      const channel = await openSftp(wire);
      requireSftpPacket(parseSftpInit(await readSftpChannelPacket(wire, channel.remote)));
      await wire.writePayload(formatChannelClose(channel.local));
    },
  });
  const client = await connectClient(peer.transport, clientKey);
  const opening = client.openSftp();
  await rejects(() => opening, SSHClientError);
  await server;
  strictEqual(peer.transport.readable.locked, false);
  strictEqual(peer.transport.writable.locked, false);
  strictEqual(peer.closeCalls, 1);
});

test("managed client rejects an individual oversized packet", async () => {
  const clientKey = await generateEd25519KeyPair();
  const packetLength = new Uint8Array(4);
  new DataView(packetLength.buffer).setUint32(0, 257);
  const transport = fixedTransport(joinBytes(new TextEncoder().encode("SSH-2.0-fake-server\r\n"), packetLength));
  await rejects(
    () =>
      connect({
        transport,
        host: { hostname: "ssh.example.test" },
        username: "alicia",
        credential: clientKey,
        hostVerifier: { verify: async () => undefined },
        maximumPacketLength: 256,
      }),
    SSHClientError,
  );
  strictEqual(transport.readable.locked, false);
  strictEqual(transport.writable.locked, false);
  strictEqual(transport.closeCalls, 1);
});

const supportsLocalTcp = hasLocalTcpCapability();

test("connectTcp exchanges bytes with a local TCP server", { skip: !supportsLocalTcp }, async () => {
  const server = await createTcpEchoServer();
  try {
    const transport = await connectTcp("127.0.0.1", server.port);
    const writer = transport.writable.getWriter();
    await writer.write(Uint8Array.of(1, 2, 3));
    writer.releaseLock();
    const reader = transport.readable.getReader();
    const result = await reader.read();
    deepStrictEqual(result.value, Uint8Array.of(1, 2, 3));
    reader.releaseLock();
    await transport.close?.();
  } finally {
    await server.close();
  }
});

test("connectTcp aborts before opening a local TCP connection", { skip: !supportsLocalTcp }, async () => {
  const server = await createTcpEchoServer();
  try {
    const controller = new AbortController();
    controller.abort(new Error("cancelled"));
    await rejects(() => connectTcp("127.0.0.1", server.port, { signal: controller.signal }), SSHClientError);
    strictEqual(server.connections(), 0);
  } finally {
    await server.close();
  }
});

test("connectTcp aborts a pending local TCP connection", { skip: !supportsLocalTcp }, async () => {
  const server = await createTcpEchoServer();
  try {
    const controller = new AbortController();
    const connecting = connectTcp("127.0.0.1", server.port, { signal: controller.signal });
    controller.abort(new Error("cancelled"));
    await rejects(() => connecting, SSHClientError);
  } finally {
    await server.close();
  }
});

test("connectTcp validates adapter inputs with typed errors", async () => {
  await rejects(() => connectTcp("bad\0host"), SSHClientError);
  await rejects(() => connectTcp("example.test", 0), SSHClientError);
});

type ServerEndpoint = { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };

type TcpEchoServer = {
  port: number;
  connections(): number;
  close(): Promise<void>;
};

type DenoTestConnection = {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
};

type DenoTestListener = {
  addr: { port?: unknown };
  accept(): Promise<DenoTestConnection>;
  close(): void;
};

type DenoTest = {
  listen(options: { hostname: string; port: number }): DenoTestListener;
};

type NodeTestSocket = {
  on(event: string, listener: (...args: unknown[]) => void): unknown;
  write(chunk: Uint8Array): boolean;
};

type NodeTestServer = {
  address(): { port?: unknown } | string | null;
  close(callback: (error?: unknown) => void): unknown;
  once(event: string, listener: (...args: unknown[]) => void): unknown;
  removeListener(event: string, listener: (...args: unknown[]) => void): unknown;
  listen(port: number, host: string): unknown;
};

type NodeTestNet = {
  createServer(listener: (socket: NodeTestSocket) => void): NodeTestServer;
};

function hasLocalTcpCapability(): boolean {
  return getDenoTest() !== undefined || getNodeTestNet() !== undefined;
}

async function createTcpEchoServer(): Promise<TcpEchoServer> {
  const deno = getDenoTest();
  if (deno)
    return await createDenoTcpEchoServer(deno);
  const net = getNodeTestNet();
  if (net)
    return await createNodeTcpEchoServer(net);
  throw new Error("local TCP is unavailable");
}

function getDenoTest(): DenoTest | undefined {
  const deno = (globalThis as { Deno?: unknown }).Deno;
  if (!deno || typeof deno !== "object" || !("listen" in deno) || typeof deno.listen !== "function")
    return undefined;
  return deno as DenoTest;
}

function getNodeTestNet(): NodeTestNet | undefined {
  const process = (globalThis as { process?: { getBuiltinModule?: (name: string) => unknown } }).process;
  const net = process?.getBuiltinModule?.("node:net");
  if (!net || typeof net !== "object" || !("createServer" in net) || typeof net.createServer !== "function")
    return undefined;
  return net as NodeTestNet;
}

function createDenoTcpEchoServer(deno: DenoTest): Promise<TcpEchoServer> {
  const listener = deno.listen({ hostname: "127.0.0.1", port: 0 });
  if (typeof listener.addr.port !== "number") {
    listener.close();
    throw new Error("Deno TCP listener did not provide a port");
  }
  let connections = 0;
  let closed = false;
  void listener.accept().then(
    async (connection) => {
      connections++;
      try {
        await connection.readable.pipeTo(connection.writable);
      } catch {
        // Closing either side of the test connection ends the echo pump.
      }
    },
    () => {
      if (!closed)
        throw new Error("Deno TCP listener failed to accept a connection");
    },
  );
  return Promise.resolve({
    port: listener.addr.port,
    connections: () => connections,
    close() {
      closed = true;
      listener.close();
      return Promise.resolve();
    },
  });
}

async function createNodeTcpEchoServer(net: NodeTestNet): Promise<TcpEchoServer> {
  let connections = 0;
  const server = net.createServer((socket) => {
    connections++;
    socket.on("data", (chunk) => {
      if (chunk instanceof Uint8Array)
        socket.write(chunk);
    });
  });
  await new Promise<void>((resolve, reject) => {
    const listening = () => {
      server.removeListener("error", failed);
      resolve();
    };
    const failed = (error: unknown) => {
      server.removeListener("listening", listening);
      reject(error);
    };
    server.once("listening", listening);
    server.once("error", failed);
    server.listen(0, "127.0.0.1");
  });
  const address = server.address();
  if (!address || typeof address === "string" || typeof address.port !== "number") {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error === undefined ? resolve() : reject(error))
    );
    throw new Error("Node TCP listener did not provide a port");
  }
  return {
    port: address.port,
    connections: () => connections,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => error === undefined ? resolve() : reject(error));
      }),
  };
}

function createPeer(): {
  transport: SSHTransport & { closeCalls: number };
  server: ServerEndpoint;
  closeCalls: number;
} {
  const clientToServer = new TransformStream<Uint8Array, Uint8Array>(undefined, undefined, { highWaterMark: 1 });
  const serverToClient = new TransformStream<Uint8Array, Uint8Array>(undefined, undefined, { highWaterMark: 1 });
  const transport = {
    readable: serverToClient.readable,
    writable: clientToServer.writable,
    closeCalls: 0,
    close() {
      this.closeCalls++;
    },
  };
  return {
    transport,
    server: { readable: clientToServer.readable, writable: serverToClient.writable },
    get closeCalls() {
      return transport.closeCalls;
    },
  };
}

function trackedTransport(
  closeImmediately = false,
): { transport: SSHTransport & { closeCalls: number }; closeCalls: number } {
  let readableController: ReadableStreamDefaultController<Uint8Array> | undefined;
  const transport = {
    readable: new ReadableStream<Uint8Array>({
      start(controller) {
        readableController = controller;
      },
    }),
    writable: new WritableStream<Uint8Array>(),
    closeCalls: 0,
    close() {
      this.closeCalls++;
      readableController?.close();
    },
  };
  if (closeImmediately)
    readableController?.close();
  return {
    transport,
    get closeCalls() {
      return transport.closeCalls;
    },
  };
}

function fixedTransport(bytes: Uint8Array): SSHTransport & { closeCalls: number } {
  return {
    readable: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes);
      },
    }),
    writable: new WritableStream<Uint8Array>(),
    closeCalls: 0,
    close() {
      this.closeCalls++;
    },
  };
}

async function connectClient(
  transport: SSHTransport,
  credential: Awaited<ReturnType<typeof generateEd25519KeyPair>>,
) {
  return await connect({
    transport,
    host: { hostname: "ssh.example.test" },
    username: "alicia",
    credential,
    hostVerifier: { verify: async () => undefined },
  });
}

async function openExec(wire: ServerWire, command: string): Promise<{ local: number; remote: number }> {
  const open = parseSessionChannelOpen(await wire.readPayload());
  const remote = 27;
  await wire.writePayload(
    formatChannelOpenConfirmation({
      recipientChannel: open.senderChannel,
      senderChannel: remote,
      initialWindowSize: 1_048_576,
      maximumPacketSize: 32_768,
    }),
  );
  const request = parseExecChannelRequest(await wire.readPayload());
  strictEqual(request.recipientChannel, remote);
  strictEqual(request.wantReply, true);
  strictEqual(request.command, command);
  await wire.writePayload(formatChannelRequestSuccess(open.senderChannel));
  strictEqual(parseChannelEof(await wire.readPayload()), remote);
  return { local: open.senderChannel, remote };
}

async function openSftp(
  wire: ServerWire,
  maximumPacketSize = 32_768,
  initialWindowSize = 65_536,
): Promise<{ local: number; remote: number }> {
  const open = parseSessionChannelOpen(await wire.readPayload());
  const remote = 29;
  await wire.writePayload(
    formatChannelOpenConfirmation({
      recipientChannel: open.senderChannel,
      senderChannel: remote,
      initialWindowSize,
      maximumPacketSize,
    }),
  );
  const request = parseSubsystemChannelRequest(await wire.readPayload());
  strictEqual(request.recipientChannel, remote);
  strictEqual(request.wantReply, true);
  strictEqual(request.subsystem, "sftp");
  await wire.writePayload(formatChannelRequestSuccess(open.senderChannel));
  return { local: open.senderChannel, remote };
}

async function readSftpChannelPacket(wire: ServerWire, remoteChannel: number): Promise<Uint8Array> {
  let bytes = new Uint8Array();
  while (true) {
    const payload = await wire.readPayload();
    if (payload[0] === 93) {
      parseChannelWindowAdjust(payload);
      continue;
    }
    if (payload[0] !== 94)
      throw new Error("expected SSH channel data carrying SFTP");
    const data = parseChannelData(payload);
    strictEqual(data.recipientChannel, remoteChannel);
    const joined = new Uint8Array(bytes.length + data.data.length);
    joined.set(bytes);
    joined.set(data.data, bytes.length);
    bytes = joined;
    const packet = readSftpPacket(bytes);
    if (packet && packet.consumed === bytes.length)
      return bytes;
  }
}

async function readSftpChannelData(wire: ServerWire, remoteChannel: number): Promise<Uint8Array> {
  while (true) {
    const payload = await wire.readPayload();
    if (payload[0] === 93) {
      parseChannelWindowAdjust(payload);
      continue;
    }
    if (payload[0] !== 94)
      throw new Error("expected SSH channel data carrying SFTP");
    const data = parseChannelData(payload);
    strictEqual(data.recipientChannel, remoteChannel);
    return data.data;
  }
}

async function closeSftpChannel(wire: ServerWire, channel: { local: number; remote: number }): Promise<void> {
  let receivedEof = false;
  while (true) {
    const payload = await wire.readPayload();
    if (payload[0] === 93) {
      parseChannelWindowAdjust(payload);
      continue;
    }
    if (payload[0] === 96) {
      strictEqual(parseChannelEof(payload), channel.remote);
      receivedEof = true;
      continue;
    }
    if (payload[0] === 97) {
      strictEqual(receivedEof, true);
      strictEqual(parseChannelClose(payload), channel.remote);
      await writeFragmentedPayloads(wire, formatChannelEof(channel.local), formatChannelClose(channel.local));
      return;
    }
    throw new Error("expected SSH SFTP channel shutdown");
  }
}

function requireSftpPacket<T>(packet: T | undefined): T {
  if (!packet)
    throw new Error("expected complete SFTP packet");
  return packet;
}

async function writeFragmentedPayloads(wire: ServerWire, ...payloads: Uint8Array[]): Promise<void> {
  if (!wire.outboundCipher)
    throw new Error("expected encrypted server wire");
  const packets: Uint8Array[] = [];
  for (const payload of payloads)
    packets.push(await wire.outboundCipher.encrypt(payload));
  const bytes = joinBytes(...packets);
  const middle = Math.max(1, Math.floor(bytes.length / 3));
  await wire.writeBytes(bytes.subarray(0, middle));
  await wire.writeBytes(bytes.subarray(middle, middle * 2));
  await wire.writeBytes(bytes.subarray(middle * 2));
}

async function expectWindowAdjustments(wire: ServerWire, channel: number, count: number): Promise<void> {
  for (let index = 0; index < count; index++) {
    const adjustment = parseChannelWindowAdjust(await wire.readPayload());
    strictEqual(adjustment.recipientChannel, channel);
  }
}

async function serve(
  server: ServerEndpoint,
  hostKey: Awaited<ReturnType<typeof generateEd25519KeyPair>>,
  clientKey: Awaited<ReturnType<typeof generateEd25519KeyPair>>["publicKey"],
  corruptSignature = false,
  options: Readonly<{ coalescePackets?: boolean; onAuthenticated?: (wire: ServerWire) => Promise<void> }> = {},
): Promise<void> {
  const wire = new ServerWire(server);
  try {
    const serverKexInit = formatKexInit(kexInit(options.coalescePackets));
    if (options.coalescePackets) {
      await wire.writeBytes(
        joinBytes(
          new TextEncoder().encode("preamble lines\r\nSSH-2.0-fake-server\r\n"),
          formatPacket(serverKexInit),
        ),
      );
    } else {
      await wire.writeBytes(new TextEncoder().encode("SSH-2.0-fake-server\r\n"));
      await wire.writePayload(serverKexInit);
    }
    const clientIdentification = await wire.readIdentification();
    const clientKexInit = await wire.readPayload();
    parseKexInit(clientKexInit);
    const clientPublic = parseKexEcdhInit(await wire.readPayload());
    const ephemeral = await generateX25519KeyPair();
    const sharedSecret = await deriveX25519Secret(ephemeral.privateKey, clientPublic);
    const exchangeHash = await computeCurve25519Sha256ExchangeHash({
      clientIdentification,
      serverIdentification: "SSH-2.0-fake-server",
      clientKexInit,
      serverKexInit,
      hostKey: hostKey.publicKey.marshal(),
      clientPublic,
      serverPublic: ephemeral.publicKey,
      sharedSecret,
    });
    const signature = (await signEd25519(hostKey.privateKey, exchangeHash)).marshal();
    if (corruptSignature)
      signature[signature.length - 1] ^= 1;
    await wire.writePayload(
      formatKexEcdhReply({ hostKey: hostKey.publicKey.marshal(), serverPublic: ephemeral.publicKey, signature }),
    );
    parseNewKeys(await wire.readPayload());
    await wire.writePayload(formatNewKeys());
    wire.inboundCipher = await createAes128CtrHmacSha256Cipher(
      sharedSecret,
      exchangeHash,
      exchangeHash,
      "client-to-server",
    );
    wire.outboundCipher = await createAes128CtrHmacSha256Cipher(
      sharedSecret,
      exchangeHash,
      exchangeHash,
      "server-to-client",
    );
    strictEqual(parseServiceRequest(await wire.readPayload()), "ssh-userauth");
    await wire.writePayload(formatServiceAccept("ssh-userauth"));
    const request = parseUserAuthPublicKeyRequest(await wire.readPayload());
    strictEqual(request.username, "alicia");
    if (!request.signature)
      throw new Error("expected signed authentication request");
    strictEqual(
      await verifyEd25519Signature(
        clientKey,
        request.signature,
        formatUserAuthPublicKeySignatureData(exchangeHash, request),
      ),
      true,
    );
    if (options.coalescePackets) {
      await wire.writeBytes(
        joinBytes(
          await wire.outboundCipher.encrypt(formatUserAuthSuccess()),
          await wire.outboundCipher.encrypt(formatIgnore(new Uint8Array(34_950))),
        ),
      );
    } else {
      await wire.writePayload(formatUserAuthSuccess());
    }
    await options.onAuthenticated?.(wire);
  } finally {
    wire.release();
  }
}

class ServerWire {
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>;
  readonly #writer: WritableStreamDefaultWriter<Uint8Array>;
  #buffer = new Uint8Array();
  inboundCipher?: SSHAesCtrHmacSha256;
  outboundCipher?: SSHAesCtrHmacSha256;

  constructor(endpoint: ServerEndpoint) {
    this.#reader = endpoint.readable.getReader();
    this.#writer = endpoint.writable.getWriter();
  }

  async readIdentification(): Promise<string> {
    while (true) {
      const lineEnd = this.#buffer.indexOf(10);
      if (lineEnd !== -1) {
        const line = this.#buffer.slice(0, lineEnd + 1);
        this.#buffer = this.#buffer.slice(lineEnd + 1);
        return new TextDecoder().decode(line).trimEnd();
      }
      await this.#readMore();
    }
  }

  async readPayload(): Promise<Uint8Array> {
    while (true) {
      const packet = this.inboundCipher ? await this.inboundCipher.read(this.#buffer) : readPacket(this.#buffer);
      if (packet) {
        this.#buffer = this.#buffer.slice(packet.consumed);
        return packet.payload;
      }
      await this.#readMore();
    }
  }

  writeBytes(bytes: Uint8Array): Promise<void> {
    return this.#writer.write(bytes);
  }

  async writePayload(payload: Uint8Array): Promise<void> {
    await this.writeBytes(this.outboundCipher ? await this.outboundCipher.encrypt(payload) : formatPacket(payload));
  }

  release(): void {
    this.#reader.releaseLock();
    this.#writer.releaseLock();
  }

  async #readMore(): Promise<void> {
    const result = await this.#reader.read();
    if (result.done)
      throw new Error("client closed test transport");
    const merged = new Uint8Array(this.#buffer.length + result.value.length);
    merged.set(this.#buffer);
    merged.set(result.value, this.#buffer.length);
    this.#buffer = merged;
  }
}

function kexInit(largeLanguageList = false) {
  return {
    cookie: Uint8Array.from({ length: 16 }, (_, index) => index),
    kexAlgorithms: ["curve25519-sha256"],
    serverHostKeyAlgorithms: ["ssh-ed25519"],
    encryptionAlgorithmsClientToServer: ["aes128-ctr"],
    encryptionAlgorithmsServerToClient: ["aes128-ctr"],
    macAlgorithmsClientToServer: ["hmac-sha2-256"],
    macAlgorithmsServerToClient: ["hmac-sha2-256"],
    compressionAlgorithmsClientToServer: ["none"],
    compressionAlgorithmsServerToClient: ["none"],
    languagesClientToServer: [],
    languagesServerToClient: largeLanguageList ? [...Array(536).fill("x".repeat(64)), "x"] : [],
    firstKexPacketFollows: false,
  };
}

function joinBytes(...chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const joined = new Uint8Array(length);
  let start = 0;
  for (const chunk of chunks) {
    joined.set(chunk, start);
    start += chunk.length;
  }
  return joined;
}
