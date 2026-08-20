/** SSH protocol version information from an identification line. */
export type SSHIdentification = {
    protocolVersion: "2.0" | "1.99";
    softwareVersion: string;
    comments?: string;
};
/** A complete identification line and the bytes consumed to read it. */
export type SSHIdentificationReadResult = {
    identification: SSHIdentification;
    consumed: number;
};
/** Error raised when an SSH identification line is invalid. */
export declare class SSHIdentificationError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Parses an SSH identification line without its CRLF terminator. */
export declare function parseIdentification(line: string): SSHIdentification;
/** Formats an SSH identification value as an RFC 4253 CRLF-terminated line. */
export declare function formatIdentification(identification: SSHIdentification): string;
/**
 * Reads an SSH identification line from bytes, skipping RFC 4253 preamble lines.
 * Returns undefined when more input is required.
 */
export declare function readIdentification(input: Uint8Array, maximumLineLength?: number): SSHIdentificationReadResult | undefined;
