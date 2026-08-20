/** Error raised when an SSH identification line is invalid. */
export class SSHIdentificationError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHIdentificationError";
    }
}
/** Parses an SSH identification line without its CRLF terminator. */
export function parseIdentification(line) {
    if (!line.startsWith("SSH-"))
        throw new SSHIdentificationError("SSH identification must start with SSH-");
    assertPrintableAscii(line, "SSH identification");
    const versionEnd = line.indexOf("-", 4);
    if (versionEnd === -1)
        throw new SSHIdentificationError("SSH identification is missing a software version");
    const protocolVersion = line.slice(4, versionEnd);
    if (protocolVersion !== "2.0" && protocolVersion !== "1.99") {
        throw new SSHIdentificationError(`unsupported SSH protocol version: ${protocolVersion}`);
    }
    const commentStart = line.indexOf(" ", versionEnd + 1);
    const softwareVersion = line.slice(versionEnd + 1, commentStart === -1 ? line.length : commentStart);
    if (!softwareVersion)
        throw new SSHIdentificationError("SSH software version must not be empty");
    if (softwareVersion.includes(" "))
        throw new SSHIdentificationError("SSH software version must not contain spaces");
    const comments = commentStart === -1 ? undefined : line.slice(commentStart + 1);
    if (comments === "")
        throw new SSHIdentificationError("SSH comments must not be empty");
    return { protocolVersion, softwareVersion, comments };
}
/** Formats an SSH identification value as an RFC 4253 CRLF-terminated line. */
export function formatIdentification(identification) {
    const { protocolVersion, softwareVersion, comments } = identification;
    if (protocolVersion !== "2.0" && protocolVersion !== "1.99") {
        throw new SSHIdentificationError(`unsupported SSH protocol version: ${protocolVersion}`);
    }
    if (!softwareVersion)
        throw new SSHIdentificationError("SSH software version must not be empty");
    assertPrintableAscii(softwareVersion, "SSH software version");
    if (softwareVersion.includes(" "))
        throw new SSHIdentificationError("SSH software version must not contain spaces");
    if (comments !== undefined) {
        if (!comments)
            throw new SSHIdentificationError("SSH comments must not be empty");
        assertPrintableAscii(comments, "SSH comments");
    }
    return `SSH-${protocolVersion}-${softwareVersion}${comments === undefined ? "" : ` ${comments}`}\r\n`;
}
/**
 * Reads an SSH identification line from bytes, skipping RFC 4253 preamble lines.
 * Returns undefined when more input is required.
 */
export function readIdentification(input, maximumLineLength = 255) {
    if (!Number.isSafeInteger(maximumLineLength) || maximumLineLength < 1) {
        throw new SSHIdentificationError("maximum SSH identification line length must be a positive safe integer");
    }
    let start = 0;
    for (let index = 0; index < input.length; index++) {
        if (input[index] !== 0x0a)
            continue;
        const length = index - start + 1;
        if (length > maximumLineLength)
            throw new SSHIdentificationError("SSH identification line exceeds the maximum length");
        const end = index > start && input[index - 1] === 0x0d ? index - 1 : index;
        if (hasIdentificationPrefix(input, start, end)) {
            if (end === index)
                throw new SSHIdentificationError("SSH identification line must end with CRLF");
            return { identification: parseIdentification(decodeAscii(input, start, end)), consumed: index + 1 };
        }
        start = index + 1;
    }
    if (input.length - start > maximumLineLength)
        throw new SSHIdentificationError("SSH identification line exceeds the maximum length");
    return undefined;
}
function hasIdentificationPrefix(input, start, end) {
    return end - start >= 4 && input[start] === 0x53 && input[start + 1] === 0x53 && input[start + 2] === 0x48 &&
        input[start + 3] === 0x2d;
}
function decodeAscii(input, start, end) {
    let value = "";
    for (let index = start; index < end; index++) {
        const code = input[index];
        if (code < 0x20 || code > 0x7e)
            throw new SSHIdentificationError("SSH identification must use printable US-ASCII");
        value += String.fromCharCode(code);
    }
    return value;
}
function assertPrintableAscii(value, name) {
    for (let index = 0; index < value.length; index++) {
        const code = value.charCodeAt(index);
        if (code < 0x20 || code > 0x7e)
            throw new SSHIdentificationError(`${name} must use printable US-ASCII`);
    }
}
