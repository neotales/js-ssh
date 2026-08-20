# Neotales JavaScript SSH Libraries

Deno-first TypeScript libraries for age encryption and SSH2. This repository is currently a
scaffold: it deliberately exposes no public API until the protocol and package design are planned.

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
