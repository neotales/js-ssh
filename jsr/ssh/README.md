# @neotales/ssh

Dependency-free SSH2 primitives for Deno, Node, and compatible JavaScript runtimes. The package is
under active development and does not yet provide a client or server.

## Primitives

```ts
import { SSHReader, SSHWriter } from "@neotales/ssh/primitives";

const packet = new SSHWriter().writeString(new TextEncoder().encode("ssh-ed25519")).toUint8Array();
const algorithm = new TextDecoder().decode(new SSHReader(packet).readString());
```

## Keys

```ts
import { fingerprintSHA256, parseAuthorizedKey } from "@neotales/ssh/keys";

const { key } = parseAuthorizedKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== example");
console.log(await fingerprintSHA256(key));
```

The current key API handles SSH public-key wire blobs and ordinary `authorized_keys` lines. It does
not yet validate algorithm-specific key parameters or parse key options and markers.

## License

[MIT](./LICENSE.md)
