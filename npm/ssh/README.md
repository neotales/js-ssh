# @neotales/ssh

Dependency-free SSH2 for Deno, Node, Bun, and compatible JavaScript runtimes.

This alpha publishes key and host-trust helpers plus an SFTP v3 client over a supplied SSH subsystem
channel. It is not yet an SSH TCP client; applications provide the channel after establishing the SSH
session themselves. Raw protocol codecs remain package-internal.

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
