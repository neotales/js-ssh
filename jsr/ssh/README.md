# @neotales/ssh

Dependency-free SSH2 for Deno, Node, Bun, and compatible JavaScript runtimes.

This alpha publishes key and host-trust helpers, an experimental managed SSH client core, and an SFTP
v3 client over a supplied SSH subsystem channel. Applications can supply an owned portable byte transport
or create one with `connectTcp()` where native raw TCP is available. Raw protocol codecs remain package-internal.

## Experimental Managed Client

`connect()` performs version exchange, `curve25519-sha256` key exchange with an `ssh-ed25519` host
key, `aes128-ctr`/`hmac-sha2-256` transport protection, and signed Ed25519 public-key authentication.
Host verification is mandatory and runs only after the host-key signature is valid.

```ts
import { connect, connectTcp } from "@neotales/ssh/client";

const client = await connect({
  transport: await connectTcp("example.com"),
  host: { hostname: "example.com", port: 22 },
  username: "alicia",
  credential: { publicKey, privateKey },
  hostVerifier: {
    async verify({ hostname, port, peerKey }) {
      // Compare peerKey with a pinned key or a known_hosts policy.
    },
  },
});

console.log(client.connectionInfo.peerSoftwareIdentification);
const result = await client.run("uname -a");
console.log(new TextDecoder().decode(result.stdout));
console.log(result.exitCode); // Nonzero exit codes are result data.
await client.close();
```

`run()` opens one `session` channel for an `exec` request and collects stdout and stderr in memory. Its
combined output is bounded to 1 MiB by default and can be changed with `maximumOutputBytes`. It permits
only one active command and rejects concurrent calls until general SSH channel multiplexing is added.
Aborting an active command closes the owned transport because SSH has no generic command cancellation.

`connectTcp()` is an optional asynchronous transport source for Deno, Node, Bun, and compatible runtimes
with raw TCP. It is not available in browsers, which cannot expose raw TCP; calling it there throws an
`SSHClientError`. This client is intentionally limited: it has no interactive sessions, SFTP adapter,
server API, rekeying, or algorithm negotiation policy beyond the one fixed modern profile. `close()`
currently terminates the owned transport immediately rather than sending a graceful SSH disconnect.

Browsers can use `connect()` only with an application-supplied raw-byte WebSocket or WebTransport
tunnel. The tunnel must forward opaque SSH bytes to TCP rather than terminate SSH, so this client
still verifies the destination SSH host key end-to-end. A future `@neotales/ssh-browser-tunnel` package may
provide Bun, Deno, and Node gateway adapters; it is intentionally separate from this SSH protocol
package.

## Keys and Host Trust

```ts
import { fingerprintSHA256, parseAuthorizedKey } from "@neotales/ssh/keys";

const { key } = parseAuthorizedKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== example");
console.log(await fingerprintSHA256(key));
```

The current key API handles SSH public-key wire blobs and ordinary `authorized_keys` lines. It
validates the supported public-key blob structures, but does not yet parse key options and markers.

`@neotales/ssh/known_hosts` parses and verifies OpenSSH `known_hosts` entries, including wildcard,
negated, hashed, and revoked hosts.

## SFTP

`SFTPClient` operates over a supplied SSH `sftp` subsystem channel. It handles v3 negotiation,
fragmented channel data, request IDs, opaque handles, and status responses internally.

```ts
import { SFTPClient } from "@neotales/ssh/sftp";

const sftp = await SFTPClient.connect(channel);
await sftp.upload("reports/today.txt", new TextEncoder().encode("complete\n"));

for await (const entry of sftp.readDir("reports"))
  console.log(entry.filename, entry.attributes.size);

const reader = sftp.download("reports/today.txt").getReader();
// Consume the readable stream, then close SFTP to close its subsystem channel.
```

`SFTPClient.connect()` takes ownership of the supplied subsystem channel after acquiring its stream
locks. Closing the SFTP client closes that channel, but an SSH-owned adapter must not close the
parent SSH connection. Closing a future parent SSH client will terminate all child channels.

## API Direction

The public API will be promise- and Web-stream-first rather than an event-emitter or callback layer:

- `connect()` will require explicit host-trust verification. Insecure host acceptance will be a
  conspicuously named opt-in, never the default.
- A connected client will open sessions for commands, shells, and subsystems. Commands will expose
  `stdin`, `stdout`, `stderr`, and `wait()` so output can be consumed without event-order races.
- `client.sftp()` will return a high-level SFTP client for files, directories, and streaming uploads
  and downloads. It will allocate request IDs and route responses internally; bounded transfer
  pipelining will follow.
- Servers will use async policy handlers and typed session requests. They will reject unhandled
  channels and requests by default instead of requiring consumers to drain raw protocol queues.
- Connection, channel, SFTP, and server operations will accept `AbortSignal`, apply bounded limits,
  and return typed errors with safe metadata.

The implementation will use portable `Uint8Array` values and Web streams at its public boundary.
Node and Deno sockets will be adapters, not required public types.

## License

[MIT](./LICENSE.md)
