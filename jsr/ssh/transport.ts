/**
 * SSH transport-control messages for disconnects and diagnostics.
 *
 * @module @neotales/ssh/transport
 */

export {
  formatDebug,
  formatDisconnect,
  formatIgnore,
  formatUnimplemented,
  parseDebug,
  parseDisconnect,
  parseIgnore,
  parseUnimplemented,
  type SSHDebug,
  type SSHDisconnect,
  SSHTransportError,
} from "./src/transport.ts";
