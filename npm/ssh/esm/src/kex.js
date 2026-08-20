import { SSHReader, SSHWriter } from "./wire.js";
const SSH_MSG_KEXINIT = 20;
/** Error raised when an SSH key-exchange message is malformed. */
export class SSHKexError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHKexError";
    }
}
/** Parses a complete SSH_MSG_KEXINIT payload. */
export function parseKexInit(payload) {
    const reader = new SSHReader(payload);
    if (reader.readByte() !== SSH_MSG_KEXINIT)
        throw new SSHKexError("expected SSH_MSG_KEXINIT");
    const cookie = new Uint8Array(16);
    for (let index = 0; index < cookie.length; index++) {
        cookie[index] = reader.readByte();
    }
    const init = {
        cookie,
        kexAlgorithms: reader.readNameList(),
        serverHostKeyAlgorithms: reader.readNameList(),
        encryptionAlgorithmsClientToServer: reader.readNameList(),
        encryptionAlgorithmsServerToClient: reader.readNameList(),
        macAlgorithmsClientToServer: reader.readNameList(),
        macAlgorithmsServerToClient: reader.readNameList(),
        compressionAlgorithmsClientToServer: reader.readNameList(),
        compressionAlgorithmsServerToClient: reader.readNameList(),
        languagesClientToServer: reader.readNameList(),
        languagesServerToClient: reader.readNameList(),
        firstKexPacketFollows: reader.readBoolean(),
    };
    if (reader.readUint32() !== 0)
        throw new SSHKexError("SSH_MSG_KEXINIT reserved field must be zero");
    reader.assertDone();
    validateKexInit(init);
    return init;
}
/** Formats an SSH_MSG_KEXINIT payload. */
export function formatKexInit(init) {
    validateKexInit(init);
    const writer = new SSHWriter().writeByte(SSH_MSG_KEXINIT);
    for (const byte of init.cookie) {
        writer.writeByte(byte);
    }
    writer
        .writeNameList(init.kexAlgorithms)
        .writeNameList(init.serverHostKeyAlgorithms)
        .writeNameList(init.encryptionAlgorithmsClientToServer)
        .writeNameList(init.encryptionAlgorithmsServerToClient)
        .writeNameList(init.macAlgorithmsClientToServer)
        .writeNameList(init.macAlgorithmsServerToClient)
        .writeNameList(init.compressionAlgorithmsClientToServer)
        .writeNameList(init.compressionAlgorithmsServerToClient)
        .writeNameList(init.languagesClientToServer)
        .writeNameList(init.languagesServerToClient)
        .writeBoolean(init.firstKexPacketFollows)
        .writeUint32(0);
    return writer.toUint8Array();
}
/** Selects algorithms using the client proposal's preference order. */
export function negotiateKexInit(client, server) {
    return {
        kexAlgorithm: selectRequired(client.kexAlgorithms, server.kexAlgorithms, "key exchange"),
        serverHostKeyAlgorithm: selectRequired(client.serverHostKeyAlgorithms, server.serverHostKeyAlgorithms, "server host key"),
        encryptionAlgorithmClientToServer: selectRequired(client.encryptionAlgorithmsClientToServer, server.encryptionAlgorithmsClientToServer, "client-to-server encryption"),
        encryptionAlgorithmServerToClient: selectRequired(client.encryptionAlgorithmsServerToClient, server.encryptionAlgorithmsServerToClient, "server-to-client encryption"),
        macAlgorithmClientToServer: selectRequired(client.macAlgorithmsClientToServer, server.macAlgorithmsClientToServer, "client-to-server MAC"),
        macAlgorithmServerToClient: selectRequired(client.macAlgorithmsServerToClient, server.macAlgorithmsServerToClient, "server-to-client MAC"),
        compressionAlgorithmClientToServer: selectRequired(client.compressionAlgorithmsClientToServer, server.compressionAlgorithmsClientToServer, "client-to-server compression"),
        compressionAlgorithmServerToClient: selectRequired(client.compressionAlgorithmsServerToClient, server.compressionAlgorithmsServerToClient, "server-to-client compression"),
        languageClientToServer: selectOptional(client.languagesClientToServer, server.languagesClientToServer),
        languageServerToClient: selectOptional(client.languagesServerToClient, server.languagesServerToClient),
    };
}
/** Reports whether a proposal's first key-exchange and host-key choices match the negotiated result. */
export function isKexGuessCorrect(proposal, selection) {
    return proposal.kexAlgorithms[0] === selection.kexAlgorithm &&
        proposal.serverHostKeyAlgorithms[0] === selection.serverHostKeyAlgorithm;
}
function validateKexInit(init) {
    if (init.cookie.length !== 16)
        throw new SSHKexError("SSH_MSG_KEXINIT cookie must contain exactly 16 bytes");
    assertNonEmpty(init.kexAlgorithms, "key exchange");
    assertNonEmpty(init.serverHostKeyAlgorithms, "server host key");
    assertNonEmpty(init.encryptionAlgorithmsClientToServer, "client-to-server encryption");
    assertNonEmpty(init.encryptionAlgorithmsServerToClient, "server-to-client encryption");
    assertNonEmpty(init.macAlgorithmsClientToServer, "client-to-server MAC");
    assertNonEmpty(init.macAlgorithmsServerToClient, "server-to-client MAC");
    assertNonEmpty(init.compressionAlgorithmsClientToServer, "client-to-server compression");
    assertNonEmpty(init.compressionAlgorithmsServerToClient, "server-to-client compression");
}
function assertNonEmpty(value, name) {
    if (value.length === 0)
        throw new SSHKexError(`SSH_MSG_KEXINIT ${name} algorithms must not be empty`);
}
function selectRequired(client, server, name) {
    const selected = selectOptional(client, server);
    if (selected === undefined)
        throw new SSHKexError(`SSH_MSG_KEXINIT has no shared ${name} algorithm`);
    return selected;
}
function selectOptional(client, server) {
    for (const algorithm of client) {
        if (server.includes(algorithm))
            return algorithm;
    }
    return undefined;
}
