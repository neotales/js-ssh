/**
 * OpenSSH known_hosts parsing, formatting, and matching.
 *
 * @module @neotales/ssh/known_hosts
 */

export {
  hashKnownHost,
  type HostKeyStatus,
  type KnownHost,
  type KnownHostMarker,
  matchesKnownHost,
  parseKnownHost,
  parseKnownHosts,
  verifyKnownHost,
} from "./src/known_host.ts";
