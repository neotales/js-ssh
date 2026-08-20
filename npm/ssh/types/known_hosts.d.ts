/**
 * OpenSSH known_hosts parsing, formatting, and matching.
 *
 * @module @neotales/ssh/known_hosts
 */
export { hashKnownHost, type KnownHost, type KnownHostMarker, matchesKnownHost, parseKnownHost, parseKnownHosts, } from "./src/known_host.js";
