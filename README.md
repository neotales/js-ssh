# Neotales JavaScript SSH Libraries

Deno-first TypeScript libraries for age encryption and SSH2. The SSH package includes an experimental
managed client core over an application-supplied portable byte transport.

## Experimental SSH Client

The managed client performs version exchange, fixed `curve25519-sha256`/`ssh-ed25519` key exchange,
`aes128-ctr` with `hmac-sha2-256`, mandatory asynchronous host verification, and signed Ed25519
public-key authentication.

```ts
import { connect, connectTcp } from "@neotales/ssh/client";

const client = await connect({
  transport: await connectTcp("example.com"), // Optional raw TCP transport source.
  host: { hostname: "example.com" },
  username: "alicia",
  credential: { publicKey, privateKey },
  hostVerifier: { verify: async ({ peerKey }) => verifyPinnedHostKey(peerKey) },
});

const result = await client.run("uname -a");
console.log(new TextDecoder().decode(result.stdout));
console.log(result.exitCode); // Nonzero exit codes are result data.
await client.close();
```

`run()` collects combined stdout and stderr in memory, bounded to 1 MiB by default or
`maximumOutputBytes`. It currently permits exactly one active command and rejects concurrent calls;
general SSH channel multiplexing is not available yet. `client.openSftp()` opens a managed SFTP v3
subsystem and returns `SFTPClient`; it is also exclusive with `run()`, and closing that SFTP client releases
the lease so a later command can run. Aborting an active command or SFTP open, or a channel protocol failure,
closes the owned transport because this single-reader client cannot safely recover from a desynchronized
channel. `connectTcp()` is available only in Deno, Node, Bun, and other runtimes that expose raw TCP;
browsers do not provide that capability. Applications can instead supply their own transport and must provide
a rejecting-by-default host-verification policy. There is no server API in this core yet. `close()` currently
terminates the owned transport immediately rather than performing graceful SSH shutdown.

Browsers require an application-supplied raw-byte WebSocket or WebTransport tunnel that forwards
opaque SSH bytes to TCP. The browser client must still verify the destination SSH host key; tunnel TLS
does not replace SSH host verification. A future `@neotales/ssh-browser-tunnel` package is planned for Bun,
Deno, and Node gateway adapters and is intentionally separate from `@neotales/ssh`.

## Scope

The project will provide the cryptographic and key primitives shared by age and SSH, then build an
SSH client and server around those primitives. The SSH protocol surface should follow
[`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh) where JavaScript runtime
semantics permit. Higher-level client and server libraries will sit on top of that foundation.

Planned capabilities include:

- age encryption and decryption
- SSH keys, signatures, certificates, and known-host handling
- SSH2 transport, authentication, channels, session environment requests, and port forwarding
- SSH agent protocol support
- SSH client and server APIs
- SFTP and SCP
- Synchronous and asynchronous APIs where the underlying operation and runtime permit them

`node:crypto` is the primary cryptographic backend. Browser-compatible code may use Web Crypto
when its algorithms and key formats are sufficient; unsupported functionality must fail explicitly
rather than silently weakening security.

## Layout

`jsr/ssh/` contains the canonical Deno package and tests. dnt generates the self-contained ESM npm
package under `npm/ssh/`. `eng/` holds repository tasks only. Generated `esm/` JavaScript and
`types/` declarations are committed so a checkout can be consumed by path without running the
build; regenerate them rather than editing them directly.

## Development

```sh
pnpm install
deno task fmt
deno task lint
deno task build
deno task test
deno task check
```

The `test` task accepts `--node`, `--deno`, or `--bun`; without a runtime flag it runs Deno source
tests and dnt's generated Node tests. `check` runs linting, formatting validation, the dependency
audit, and those default test runtimes. `pack` creates a local npm tarball after building.

## License

[MIT](./LICENSE.md)
