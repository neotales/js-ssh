import { SSHPublicKey } from "./public_key.js";
/** OpenSSH known_hosts marker with special trust semantics. */
export type KnownHostMarker = "@cert-authority" | "@revoked";
/** One parsed, non-comment OpenSSH known_hosts line. */
export type KnownHost = {
    marker?: KnownHostMarker;
    hosts: string[];
    key: SSHPublicKey;
    comment: string;
};
/** Parses one non-comment OpenSSH known_hosts line. */
export declare function parseKnownHost(line: string): KnownHost;
/** Parses all non-comment lines from an OpenSSH known_hosts file. */
export declare function parseKnownHosts(content: string): KnownHost[];
/** Reports whether a host string matches a known_hosts entry, including hashed host patterns. */
export declare function matchesKnownHost(entry: KnownHost, host: string): Promise<boolean>;
/** Creates an OpenSSH `|1|` hashed-host pattern using the provided random salt. */
export declare function hashKnownHost(host: string, salt: Uint8Array): Promise<string>;
