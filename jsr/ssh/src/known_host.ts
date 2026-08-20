import { parseAuthorizedKey, SSHPublicKey } from "./public_key.ts";

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
export function parseKnownHost(line: string): KnownHost {
  if (line.includes("\r") || line.includes("\n")) {
    throw new Error("known_hosts input must contain exactly one line");
  }

  let offset = 0;
  let first = readField(line, offset);
  offset = first.end;
  if (!first.value)
    throw new Error("known_hosts line is empty");

  let marker: KnownHostMarker | undefined;
  if (first.value.startsWith("@")) {
    marker = parseMarker(first.value);
    offset = skipWhitespace(line, offset);
    first = readField(line, offset);
    offset = first.end;
  }

  const hosts = parseHosts(first.value);
  offset = requireWhitespace(line, offset);
  const keyType = readField(line, offset);
  offset = requireWhitespace(line, keyType.end);
  const encodedKey = readField(line, offset);
  offset = encodedKey.end;
  const commentStart = skipWhitespace(line, offset);
  const { key, comment } = parseAuthorizedKey(
    `${keyType.value} ${encodedKey.value}${commentStart < line.length ? ` ${line.slice(commentStart)}` : ""}`,
  );
  return { marker, hosts, key, comment };
}

/** Parses all non-comment lines from an OpenSSH known_hosts file. */
export function parseKnownHosts(content: string): KnownHost[] {
  const entries: KnownHost[] = [];
  let start = 0;
  while (start < content.length) {
    let end = content.indexOf("\n", start);
    if (end === -1) end = content.length;
    let line = content.slice(start, end);
    if (line.endsWith("\r")) line = line.slice(0, -1);
    const first = skipWhitespace(line, 0);
    if (first < line.length && line.charCodeAt(first) !== 0x23) {
      entries.push(parseKnownHost(line));
    }
    start = end + 1;
  }
  return entries;
}

/** Reports whether a host string matches a known_hosts entry, including hashed host patterns. */
export async function matchesKnownHost(entry: KnownHost, host: string): Promise<boolean> {
  let matched = false;
  for (const value of entry.hosts) {
    const negated = value.startsWith("!");
    const pattern = negated ? value.slice(1) : value;
    if (!pattern)
      continue;
    if (!(await matchesHostPattern(pattern, host)))
      continue;
    if (negated)
      return false;
    matched = true;
  }
  return matched;
}

/** Creates an OpenSSH `|1|` hashed-host pattern using the provided random salt. */
export async function hashKnownHost(host: string, salt: Uint8Array): Promise<string> {
  if (salt.length === 0)
    throw new Error("known_hosts hash salt cannot be empty");
  const key = await crypto.subtle.importKey("raw", ownedBytes(salt), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(host));
  return `|1|${encodeBase64(salt)}|${encodeBase64(new Uint8Array(digest))}`;
}

function parseMarker(value: string): KnownHostMarker {
  if (value === "@cert-authority" || value === "@revoked")
    return value;
  throw new Error(`unsupported known_hosts marker: ${value}`);
}

function parseHosts(value: string): string[] {
  if (!value)
    throw new Error("known_hosts host list is empty");
  const hosts: string[] = [];
  let start = 0;
  for (let index = 0; index <= value.length; index++) {
    if (index !== value.length && value.charCodeAt(index) !== 0x2c)
      continue;
    const host = value.slice(start, index);
    if (!host)
      throw new Error("known_hosts host list contains an empty pattern");
    hosts.push(host);
    start = index + 1;
  }
  return hosts;
}

function readField(text: string, start: number): { value: string; end: number } {
  let end = start;
  while (end < text.length) {
    const code = text.charCodeAt(end);
    if (code === 0x20 || code === 0x09)
      break;
    if (code < 0x21 || code > 0x7e)
      throw new Error("known_hosts fields must be printable US-ASCII");
    end++;
  }
  return { value: text.slice(start, end), end };
}

function requireWhitespace(text: string, start: number): number {
  const end = skipWhitespace(text, start);
  if (end === start)
    throw new Error("known_hosts line has too few fields");
  return end;
}

function skipWhitespace(text: string, start: number): number {
  let end = start;
  while (end < text.length && (text.charCodeAt(end) === 0x20 || text.charCodeAt(end) === 0x09)) end++;
  return end;
}

async function matchesHostPattern(pattern: string, host: string): Promise<boolean> {
  const hashed = parseHashedHost(pattern);
  if (hashed) {
    const candidate = await hashKnownHost(host, hashed.salt);
    const hash = candidate.slice(candidate.lastIndexOf("|") + 1);
    return timingSafeEqual(hash, hashed.hash);
  }
  return globMatches(pattern.toLowerCase(), host.toLowerCase());
}

function parseHashedHost(pattern: string): { salt: Uint8Array; hash: string } | undefined {
  if (!pattern.startsWith("|1|"))
    return undefined;
  const separator = pattern.indexOf("|", 3);
  if (separator === -1 || separator === pattern.length - 1)
    return undefined;
  const salt = decodeBase64(pattern.slice(3, separator));
  const hash = pattern.slice(separator + 1);
  decodeBase64(hash);
  return { salt, hash };
}

function globMatches(pattern: string, value: string): boolean {
  let patternIndex = 0;
  let valueIndex = 0;
  let starIndex = -1;
  let starValueIndex = 0;

  while (valueIndex < value.length) {
    const character = pattern.charCodeAt(patternIndex);
    if (character === 0x3f || character === value.charCodeAt(valueIndex)) {
      patternIndex++;
      valueIndex++;
    } else if (character === 0x2a) {
      starIndex = patternIndex++;
      starValueIndex = valueIndex;
    } else if (starIndex !== -1) {
      patternIndex = starIndex + 1;
      valueIndex = ++starValueIndex;
    } else {
      return false;
    }
  }
  while (pattern.charCodeAt(patternIndex) === 0x2a) patternIndex++;
  return patternIndex === pattern.length;
}

function decodeBase64(encoded: string): Uint8Array {
  try {
    const decoded = atob(encoded);
    const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    if (encodeBase64(bytes) !== encoded)
      throw new Error("noncanonical Base64");
    return bytes;
  } catch (error) {
    throw new Error("invalid known_hosts hash", { cause: error });
  }
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function ownedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(bytes.length);
  result.set(bytes);
  return result;
}

function timingSafeEqual(left: string, right: string): boolean {
  if (left.length !== right.length)
    return false;
  let different = 0;
  for (let index = 0; index < left.length; index++) {
    different |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return different === 0;
}
