# @neotales/ssh

Dependency-free SSH2 primitives for Deno, Node, and compatible JavaScript runtimes. The package is
under active development and does not yet provide a client or server.

## Primitives

```ts
import { SSHReader, SSHWriter } from "@neotales/ssh/primitives";

const packet = new SSHWriter().writeString(new TextEncoder().encode("ssh-ed25519")).toUint8Array();
const algorithm = new TextDecoder().decode(new SSHReader(packet).readString());
```

## License

[MIT](./LICENSE.md)
