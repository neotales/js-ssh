import { formatServiceRequest, formatSignedEd25519UserAuthRequest, parseServiceAccept, parseUserAuthSuccess, } from "./auth.js";
import { createAes128CtrHmacSha256Cipher } from "./cipher.js";
import { formatIdentification, readIdentification } from "./identification.js";
import { formatKexEcdhInit, formatKexInit, formatNewKeys, generateX25519KeyPair, isKexGuessCorrect, negotiateKexInit, parseKexEcdhReply, parseKexInit, parseNewKeys, verifyCurve25519Sha256Reply, } from "./kex.js";
import { formatPacket, readPacket } from "./packet.js";
import { SSHPublicKey } from "./public_key.js";
import { formatChannelClose, formatChannelData, formatChannelEof, formatChannelWindowAdjust, formatExecChannelRequest, formatSessionChannelOpen, formatSubsystemChannelRequest, parseChannelClose, parseChannelData, parseChannelEof, parseChannelExtendedData, parseChannelOpenConfirmation, parseChannelOpenFailure, parseChannelRequestFailure, parseChannelRequestSuccess, parseChannelWindowAdjust, parseExitStatus, } from "./connection.js";
import { SFTPClient } from "./sftp.js";
const DEFAULT_MAXIMUM_PACKET_LENGTH = 35_000;
const DEFAULT_SOFTWARE_VERSION = "neotales-js-ssh";
const SSH_USERAUTH_SERVICE = "ssh-userauth";
const SSH_CONNECTION_SERVICE = "ssh-connection";
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
const SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
const SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
const SSH_MSG_CHANNEL_DATA = 94;
const SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
const SSH_MSG_CHANNEL_EOF = 96;
const SSH_MSG_CHANNEL_CLOSE = 97;
const SSH_MSG_CHANNEL_REQUEST = 98;
const SSH_MSG_CHANNEL_SUCCESS = 99;
const SSH_MSG_CHANNEL_FAILURE = 100;
const DEFAULT_MAXIMUM_OUTPUT_BYTES = 1_048_576;
const DEFAULT_CHANNEL_WINDOW_SIZE = 1_048_576;
const DEFAULT_CHANNEL_MAXIMUM_PACKET_SIZE = 32_768;
const DEFAULT_SFTP_CHANNEL_WINDOW_SIZE = 65_536;
/** Safe base error for managed-client failures. */
export class SSHClientError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHClientError";
    }
}
/**
 * Opens a raw TCP transport for {@link connect} where the runtime exposes native TCP.
 *
 * This adapter is asynchronous and unavailable in browsers, which do not expose raw TCP sockets.
 */
export async function connectTcp(host, port = 22, options = {}) {
    const signal = validateConnectTcpOptions(host, port, options);
    const deno = getDenoTcp();
    try {
        if (deno) {
            const connection = await connectWithAbort(() => deno.connect({ hostname: host, port }), (value) => value.close(), signal);
            return denoTransport(connection);
        }
        const net = getNodeNet();
        if (net)
            return await connectNodeTcp(net, host, port, signal);
    }
    catch (error) {
        throw asClientError(signal?.aborted ? abortError(signal) : error);
    }
    throw new SSHClientError("raw TCP is unavailable in this runtime");
}
/** A host verifier rejection, preserving its cause without exposing peer payload bytes. */
export class SSHHostVerificationError extends SSHClientError {
    constructor(message = "SSH host verification failed", options) {
        super(message, options);
        this.name = "SSHHostVerificationError";
    }
}
/** The remote command ended without the complete SSH `exit-status`, EOF, and close sequence. */
export class SSHRemoteExitError extends SSHClientError {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHRemoteExitError";
    }
}
/**
 * An experimental authenticated SSH client.
 *
 * A client owns its transport after connecting. It does not read idle post-authentication traffic.
 * Commands and managed SFTP subsystems exclusively consume the transport while active and are serialized.
 */
export class SshClient {
    connectionInfo;
    #io;
    #leased = false;
    constructor(io, connectionInfo) {
        this.#io = io;
        this.connectionInfo = connectionInfo;
    }
    /** Creates an owning client after its handshake has completed. @internal */
    static create(io, connectionInfo) {
        return new SshClient(io, connectionInfo);
    }
    /** Immediately terminates the owned transport and rejects any pending command. */
    close(reason) {
        return this.#io.shutdown(reason);
    }
    /** Immediately aborts the owned transport. */
    abort(reason) {
        return this.#io.shutdown(reason);
    }
    /** Immediately terminates the owned transport. */
    [Symbol.asyncDispose]() {
        return this.close();
    }
    /**
     * Runs one bounded remote `exec` command on an owned `session` channel.
     *
     * Only one command may be active; another call rejects immediately rather than queuing. The result
     * resolves after remote EOF, close, and `exit-status`; a nonzero exit status is result data. Stdout
     * and stderr share `maximumOutputBytes`, which defaults to 1 MiB. If `signal` is already aborted, or
     * aborts before the initial channel-open write begins, no remote command side effect occurs. Once that
     * write begins, aborting terminates the owned transport because SSH has no generic command cancellation.
     * Any command error after that write, including a rejected request, protocol error, malformed shutdown,
     * or output-limit failure, also terminates the transport. Calling `close()` while this method is pending
     * rejects it and releases the owned stream locks.
     */
    run(command, options) {
        if (this.#leased)
            return Promise.reject(new SSHClientError("an SSH channel is already active"));
        if (this.#io.isShutdown)
            return Promise.reject(new SSHClientError("SSH client is closed"));
        this.#leased = true;
        return this.#run(command, options).finally(() => {
            this.#leased = false;
        });
    }
    /**
     * Opens one managed SFTP v3 subsystem channel.
     *
     * Commands and SFTP are serialized while this experimental client has a single SSH reader. Closing the
     * returned client closes only this subsystem channel, after which `run()` may be used again. Aborting after
     * channel opening starts, or an SFTP/SSH channel protocol failure, terminates the parent transport.
     */
    openSftp(options) {
        if (this.#leased)
            return Promise.reject(new SSHClientError("an SSH channel is already active"));
        if (this.#io.isShutdown)
            return Promise.reject(new SSHClientError("SSH client is closed"));
        this.#leased = true;
        return this.#openSftp(options).catch((error) => {
            this.#leased = false;
            throw error;
        });
    }
    async #openSftp(options) {
        const validated = validateOpenSftpOptions(options);
        let started = false;
        let abortListener;
        try {
            if (validated.signal) {
                abortListener = () => {
                    if (started)
                        void this.#io.shutdown(abortError(validated.signal));
                };
                validated.signal.addEventListener("abort", abortListener, { once: true });
                throwIfAborted(validated.signal);
            }
            const localChannel = 0;
            started = true;
            await this.#io.writePayload(formatSessionChannelOpen({
                senderChannel: localChannel,
                initialWindowSize: DEFAULT_SFTP_CHANNEL_WINDOW_SIZE,
                maximumPacketSize: DEFAULT_CHANNEL_MAXIMUM_PACKET_SIZE,
            }));
            const openReply = await this.#io.readPayload();
            let remoteChannel;
            let remoteWindow;
            let remoteMaximumPacketSize;
            switch (openReply[0]) {
                case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
                    const confirmation = parseChannelOpenConfirmation(openReply);
                    if (confirmation.recipientChannel !== localChannel)
                        throw new SSHClientError("SSH channel confirmation addressed an unknown channel");
                    remoteChannel = confirmation.senderChannel;
                    remoteWindow = confirmation.initialWindowSize;
                    remoteMaximumPacketSize = confirmation.maximumPacketSize;
                    break;
                }
                case SSH_MSG_CHANNEL_OPEN_FAILURE: {
                    const failure = parseChannelOpenFailure(openReply);
                    if (failure.recipientChannel !== localChannel)
                        throw new SSHClientError("SSH channel failure addressed an unknown channel");
                    throw new SSHClientError("SSH server rejected the SFTP session channel");
                }
                default:
                    throw new SSHClientError("received an unsupported SSH message while opening an SFTP channel");
            }
            await this.#io.writePayload(formatSubsystemChannelRequest({ recipientChannel: remoteChannel, wantReply: true, subsystem: "sftp" }));
            const subsystemReply = await this.#io.readPayload();
            if (subsystemReply[0] === SSH_MSG_CHANNEL_FAILURE) {
                if (parseChannelRequestFailure(subsystemReply) !== localChannel)
                    throw new SSHClientError("SSH subsystem failure addressed an unknown channel");
                throw new SSHClientError("SSH server rejected the SFTP subsystem request");
            }
            if (subsystemReply[0] !== SSH_MSG_CHANNEL_SUCCESS)
                throw new SSHClientError("received an unsupported SSH message while starting SFTP");
            if (parseChannelRequestSuccess(subsystemReply) !== localChannel)
                throw new SSHClientError("SSH subsystem confirmation addressed an unknown channel");
            const channel = new ManagedSftpChannel(this.#io, localChannel, remoteChannel, remoteWindow, remoteMaximumPacketSize, () => this.#leased = false);
            return await SFTPClient.connect(channel, validated);
        }
        catch (error) {
            if (started)
                await this.#io.shutdown(error);
            if (validated.signal?.aborted)
                throw abortError(validated.signal);
            throw asClientError(error);
        }
        finally {
            if (validated.signal && abortListener)
                validated.signal.removeEventListener("abort", abortListener);
        }
    }
    async #run(command, options) {
        const { signal, maximumOutputBytes } = validateRunOptions(command, options);
        let started = false;
        let abortListener;
        try {
            if (signal) {
                abortListener = () => {
                    if (started)
                        void this.#io.shutdown(abortError(signal));
                };
                signal.addEventListener("abort", abortListener, { once: true });
                throwIfAborted(signal);
            }
            const initialWindowSize = Math.min(maximumOutputBytes, DEFAULT_CHANNEL_WINDOW_SIZE);
            const localChannel = 0;
            started = true;
            await this.#io.writePayload(formatSessionChannelOpen({
                senderChannel: localChannel,
                initialWindowSize,
                maximumPacketSize: DEFAULT_CHANNEL_MAXIMUM_PACKET_SIZE,
            }));
            const openReply = await this.#io.readPayload();
            let remoteChannel;
            switch (openReply[0]) {
                case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
                    const confirmation = parseChannelOpenConfirmation(openReply);
                    if (confirmation.recipientChannel !== localChannel)
                        throw new SSHClientError("SSH channel confirmation addressed an unknown channel");
                    remoteChannel = confirmation.senderChannel;
                    break;
                }
                case SSH_MSG_CHANNEL_OPEN_FAILURE: {
                    const failure = parseChannelOpenFailure(openReply);
                    if (failure.recipientChannel !== localChannel)
                        throw new SSHClientError("SSH channel failure addressed an unknown channel");
                    throw new SSHClientError("SSH server rejected the session channel");
                }
                default:
                    throw new SSHClientError("received an unsupported SSH message while opening a channel");
            }
            await this.#io.writePayload(formatExecChannelRequest({ recipientChannel: remoteChannel, wantReply: true, command }));
            const execReply = await this.#io.readPayload();
            if (execReply[0] === SSH_MSG_CHANNEL_FAILURE) {
                if (parseChannelRequestFailure(execReply) !== localChannel)
                    throw new SSHClientError("SSH command failure addressed an unknown channel");
                throw new SSHClientError("SSH server rejected the command request");
            }
            if (execReply[0] !== SSH_MSG_CHANNEL_SUCCESS)
                throw new SSHClientError("received an unsupported SSH message while starting a command");
            if (parseChannelRequestSuccess(execReply) !== localChannel)
                throw new SSHClientError("SSH command confirmation addressed an unknown channel");
            await this.#io.writePayload(formatChannelEof(remoteChannel));
            const stdout = [];
            const stderr = [];
            let outputLength = 0;
            let receiveWindow = initialWindowSize;
            let receivedEof = false;
            let exitCode;
            while (true) {
                const payload = await this.#io.readPayload();
                switch (payload[0]) {
                    case SSH_MSG_CHANNEL_DATA: {
                        if (receivedEof)
                            throw new SSHRemoteExitError("SSH channel sent data after EOF");
                        const data = parseChannelData(payload);
                        if (data.recipientChannel !== localChannel)
                            throw new SSHClientError("SSH channel data addressed an unknown channel");
                        ({ outputLength, receiveWindow } = await this.#appendOutput(stdout, data.data, outputLength, receiveWindow, maximumOutputBytes, remoteChannel));
                        break;
                    }
                    case SSH_MSG_CHANNEL_EXTENDED_DATA: {
                        if (receivedEof)
                            throw new SSHRemoteExitError("SSH channel sent data after EOF");
                        const data = parseChannelExtendedData(payload);
                        if (data.recipientChannel !== localChannel)
                            throw new SSHClientError("SSH extended channel data addressed an unknown channel");
                        if (data.dataTypeCode !== 1)
                            throw new SSHClientError("SSH channel sent an unsupported extended-data type");
                        ({ outputLength, receiveWindow } = await this.#appendOutput(stderr, data.data, outputLength, receiveWindow, maximumOutputBytes, remoteChannel));
                        break;
                    }
                    case SSH_MSG_CHANNEL_EOF:
                        if (parseChannelEof(payload) !== localChannel)
                            throw new SSHClientError("SSH channel EOF addressed an unknown channel");
                        if (receivedEof)
                            throw new SSHRemoteExitError("SSH channel sent EOF more than once");
                        receivedEof = true;
                        break;
                    case SSH_MSG_CHANNEL_REQUEST: {
                        const status = parseExitStatus(payload);
                        if (status.recipientChannel !== localChannel)
                            throw new SSHClientError("SSH exit status addressed an unknown channel");
                        if (exitCode !== undefined)
                            throw new SSHRemoteExitError("SSH channel sent more than one exit status");
                        exitCode = status.status;
                        break;
                    }
                    case SSH_MSG_CHANNEL_CLOSE:
                        if (parseChannelClose(payload) !== localChannel)
                            throw new SSHClientError("SSH channel close addressed an unknown channel");
                        await this.#io.writePayload(formatChannelClose(remoteChannel));
                        if (!receivedEof)
                            throw new SSHRemoteExitError("SSH channel closed before EOF");
                        if (exitCode === undefined)
                            throw new SSHRemoteExitError("SSH command ended without an exit status");
                        return Object.freeze({ stdout: joinOutput(stdout), stderr: joinOutput(stderr), exitCode });
                    default:
                        throw new SSHClientError("received an unsupported SSH channel message");
                }
            }
        }
        catch (error) {
            if (started)
                await this.#io.shutdown(error);
            if (signal?.aborted)
                throw abortError(signal);
            throw asClientError(error);
        }
        finally {
            if (signal && abortListener)
                signal.removeEventListener("abort", abortListener);
        }
    }
    async #appendOutput(output, data, outputLength, receiveWindow, maximumOutputBytes, remoteChannel) {
        if (data.length > receiveWindow)
            throw new SSHClientError("SSH channel exceeded its receive window");
        if (data.length > maximumOutputBytes - outputLength)
            throw new SSHClientError("SSH command output exceeds the configured limit");
        if (data.length === 0)
            return { outputLength, receiveWindow };
        receiveWindow -= data.length;
        output.push(data.slice());
        await this.#io.writePayload(formatChannelWindowAdjust({ recipientChannel: remoteChannel, bytesToAdd: data.length }));
        return { outputLength: outputLength + data.length, receiveWindow: receiveWindow + data.length };
    }
}
/**
 * Establishes an SSH transport and authenticates with the supplied Ed25519 credential.
 *
 * The client takes ownership of `transport` only after it has acquired both stream locks.
 */
export async function connect(options) {
    const validated = validateOptions(options);
    let io;
    let abortListener;
    try {
        const reader = validated.transport.readable.getReader();
        let writer;
        try {
            writer = validated.transport.writable.getWriter();
        }
        catch (error) {
            reader.releaseLock();
            throw error;
        }
        io = new ClientIo(validated.transport, reader, writer, validated.maximumPacketLength);
        if (validated.signal) {
            const signal = validated.signal;
            abortListener = () => void io?.shutdown(abortError(signal));
            signal.addEventListener("abort", abortListener, { once: true });
            throwIfAborted(signal);
        }
        const clientIdentification = `SSH-2.0-${validated.softwareVersion}`;
        await io.writeBytes(new TextEncoder().encode(formatIdentification({ protocolVersion: "2.0", softwareVersion: validated.softwareVersion })));
        const serverIdentification = await readPeerIdentification(io);
        const clientKexInit = formatKexInit(createKexInit());
        await io.writePayload(clientKexInit);
        const serverKexInit = await io.readPayload();
        const serverProposal = parseKexInit(serverKexInit);
        const algorithms = freezeAlgorithms(negotiateKexInit(parseKexInit(clientKexInit), serverProposal));
        if (!isKexGuessCorrect(serverProposal, algorithms) && serverProposal.firstKexPacketFollows)
            await io.readPayload();
        const ephemeral = await generateX25519KeyPair();
        await io.writePayload(formatKexEcdhInit(ephemeral.publicKey));
        const verification = await verifyCurve25519Sha256Reply({
            clientIdentification,
            serverIdentification,
            clientKexInit,
            serverKexInit,
            clientPrivateKey: ephemeral.privateKey,
            clientPublicKey: ephemeral.publicKey,
            reply: parseKexEcdhReply(await io.readPayload()),
        });
        const hostContext = Object.freeze({
            hostname: validated.hostname,
            port: validated.port,
            peerKey: verification.hostKey,
            peerSoftwareIdentification: serverIdentification,
            algorithms,
        });
        try {
            await validated.hostVerifier.verify(hostContext);
        }
        catch (error) {
            throw new SSHHostVerificationError("SSH host verification failed", { cause: error });
        }
        await io.writePayload(formatNewKeys());
        io.outboundCipher = await createAes128CtrHmacSha256Cipher(verification.sharedSecret, verification.exchangeHash, verification.exchangeHash, "client-to-server", validated.maximumPacketLength);
        parseNewKeys(await io.readPayload());
        io.inboundCipher = await createAes128CtrHmacSha256Cipher(verification.sharedSecret, verification.exchangeHash, verification.exchangeHash, "server-to-client", validated.maximumPacketLength);
        await io.writePayload(formatServiceRequest(SSH_USERAUTH_SERVICE));
        if (parseServiceAccept(await io.readPayload()) !== SSH_USERAUTH_SERVICE)
            throw new SSHClientError("SSH server accepted an unexpected service");
        await io.writePayload(await formatSignedEd25519UserAuthRequest(verification.exchangeHash, {
            username: validated.username,
            service: SSH_CONNECTION_SERVICE,
            key: validated.credential.publicKey,
            privateKey: validated.credential.privateKey,
        }));
        parseUserAuthSuccess(await io.readPayload());
        if (validated.signal && abortListener)
            validated.signal.removeEventListener("abort", abortListener);
        return SshClient.create(io, Object.freeze({
            hostname: validated.hostname,
            port: validated.port,
            username: validated.username,
            peerKey: verification.hostKey,
            peerSoftwareIdentification: serverIdentification,
            algorithms,
            authenticationMethod: "publickey",
        }));
    }
    catch (error) {
        if (validated.signal && abortListener)
            validated.signal.removeEventListener("abort", abortListener);
        await io?.shutdown(error);
        throw asClientError(validated.signal?.aborted ? abortError(validated.signal) : error);
    }
}
class ClientIo {
    #transport;
    #reader;
    #writer;
    #buffer;
    #writeTail = Promise.resolve();
    #shutdown;
    inboundCipher;
    outboundCipher;
    constructor(transport, reader, writer, maximumPacketLength) {
        this.#transport = transport;
        this.#reader = reader;
        this.#writer = writer;
        this.#buffer = new ByteBuffer(maximumPacketLength);
    }
    get isShutdown() {
        return this.#shutdown !== undefined;
    }
    get bytes() {
        return this.#buffer.bytes;
    }
    consume(length) {
        this.#buffer.consume(length);
    }
    async readMore() {
        if (this.#buffer.drain())
            return;
        this.#buffer.prepareForAppend();
        const { done, value } = await this.#reader.read();
        if (done)
            throw new SSHClientError("SSH peer closed the transport");
        if (!(value instanceof Uint8Array))
            throw new SSHClientError("SSH transport produced a non-byte chunk");
        this.#buffer.append(value);
    }
    writeBytes(bytes) {
        const owned = bytes.slice();
        this.#writeTail = this.#writeTail.then(() => this.#writer.write(owned));
        return this.#writeTail;
    }
    async writePayload(payload) {
        const owned = payload.slice();
        // Cipher state advances per packet, so encryption must share the write serialization with channel controls.
        this.#writeTail = this.#writeTail.then(async () => {
            const packet = this.outboundCipher
                ? await this.outboundCipher.encrypt(owned)
                : formatPacket(owned, { maximumPacketLength: this.#buffer.maximumPacketLength });
            await this.#writer.write(packet);
        });
        await this.#writeTail;
    }
    async readPayload() {
        while (true) {
            const packet = this.inboundCipher
                ? await this.inboundCipher.read(this.#buffer.bytes)
                : readPacket(this.#buffer.bytes, { maximumPacketLength: this.#buffer.maximumPacketLength });
            if (packet) {
                this.#buffer.consume(packet.consumed);
                return packet.payload;
            }
            await this.readMore();
        }
    }
    shutdown(reason) {
        if (!this.#shutdown) {
            this.#shutdown = (async () => {
                try {
                    await this.#reader.cancel(reason);
                }
                catch { /* Preserve the primary error. */ }
                try {
                    await this.#writer.abort(reason);
                }
                catch { /* Preserve the primary error. */ }
                try {
                    await this.#transport.close?.(reason);
                }
                catch { /* Preserve the primary error. */ }
                try {
                    this.#reader.releaseLock();
                }
                catch { /* The lock may already be released. */ }
                try {
                    this.#writer.releaseLock();
                }
                catch { /* The lock may already be released. */ }
            })();
        }
        return this.#shutdown;
    }
}
/** Private SFTP channel adapter: it is the sole post-authentication SSH packet reader while leased. */
class ManagedSftpChannel {
    readable;
    writable;
    #io;
    #localChannel;
    #remoteChannel;
    #remoteMaximumPacketSize;
    #releaseLease;
    #remoteClose;
    #resolveRemoteClose;
    #rejectRemoteClose;
    #controller;
    #receiveWindow = DEFAULT_SFTP_CHANNEL_WINDOW_SIZE;
    #remoteWindow;
    #normalClosing = false;
    #sentEof = false;
    #sentClose = false;
    #closed = false;
    #released = false;
    #normalClose;
    #terminal;
    #windowWaiters = [];
    constructor(io, localChannel, remoteChannel, remoteWindow, remoteMaximumPacketSize, releaseLease) {
        this.#io = io;
        this.#localChannel = localChannel;
        this.#remoteChannel = remoteChannel;
        this.#remoteWindow = remoteWindow;
        this.#remoteMaximumPacketSize = remoteMaximumPacketSize;
        this.#releaseLease = releaseLease;
        this.#remoteClose = new Promise((resolve, reject) => {
            this.#resolveRemoteClose = resolve;
            this.#rejectRemoteClose = reject;
        });
        // Normal close awaits this promise; this observer prevents abnormal peer closure from becoming unhandled.
        void this.#remoteClose.catch(() => undefined);
        this.readable = new ReadableStream({
            start: (controller) => this.#controller = controller,
            pull: () => this.#replenishReceiveWindow(),
            cancel: (reason) => this.close(reason),
        }, {
            highWaterMark: DEFAULT_SFTP_CHANNEL_WINDOW_SIZE,
            size: (chunk) => chunk.length,
        });
        this.writable = new WritableStream({
            write: (chunk) => this.#write(chunk),
            close: () => this.close(),
            abort: (reason) => this.close(reason),
        });
        void this.#pump();
    }
    close(reason) {
        if (this.#normalClose)
            return this.#normalClose;
        if (this.#terminal)
            return this.#terminal;
        if (reason !== undefined)
            return this.#terminate(reason);
        this.#normalClosing = true;
        this.#normalClose = (async () => {
            try {
                await this.#sendEof();
                await this.#sendClose();
                await this.#remoteClose;
                this.#completeNormalClose();
            }
            catch (error) {
                await this.#terminate(error);
                throw error;
            }
        })();
        return this.#normalClose;
    }
    async #pump() {
        try {
            while (!this.#closed) {
                const payload = await this.#io.readPayload();
                switch (payload[0]) {
                    case SSH_MSG_CHANNEL_WINDOW_ADJUST: {
                        const adjust = parseChannelWindowAdjust(payload);
                        if (adjust.recipientChannel !== this.#localChannel)
                            throw new SSHClientError("SSH window adjustment addressed an unknown SFTP channel");
                        if (adjust.bytesToAdd > 0xffff_ffff - this.#remoteWindow)
                            throw new SSHClientError("SSH SFTP channel window exceeds its maximum");
                        this.#remoteWindow += adjust.bytesToAdd;
                        const waiters = this.#windowWaiters.splice(0);
                        for (const waiter of waiters)
                            waiter.resolve();
                        break;
                    }
                    case SSH_MSG_CHANNEL_DATA: {
                        if (this.#normalClosing)
                            throw new SSHClientError("SSH SFTP channel sent data while closing");
                        const data = parseChannelData(payload);
                        if (data.recipientChannel !== this.#localChannel)
                            throw new SSHClientError("SSH channel data addressed an unknown SFTP channel");
                        if (data.data.length > this.#receiveWindow)
                            throw new SSHClientError("SSH SFTP channel exceeded its receive window");
                        const available = this.#controller.desiredSize;
                        if (available === null || data.data.length > available)
                            throw new SSHClientError("SSH SFTP channel exceeded its bounded receive queue");
                        this.#receiveWindow -= data.data.length;
                        if (data.data.length > 0)
                            this.#controller.enqueue(data.data.slice());
                        break;
                    }
                    case SSH_MSG_CHANNEL_EOF:
                        if (parseChannelEof(payload) !== this.#localChannel)
                            throw new SSHClientError("SSH channel EOF addressed an unknown SFTP channel");
                        if (!this.#normalClosing)
                            throw new SSHClientError("SSH SFTP channel ended unexpectedly");
                        break;
                    case SSH_MSG_CHANNEL_CLOSE:
                        if (parseChannelClose(payload) !== this.#localChannel)
                            throw new SSHClientError("SSH channel close addressed an unknown SFTP channel");
                        if (!this.#normalClosing)
                            throw new SSHClientError("SSH SFTP channel closed unexpectedly");
                        await this.#sendClose();
                        this.#completeNormalClose();
                        this.#resolveRemoteClose();
                        break;
                    default:
                        throw new SSHClientError("received an unsupported SSH message on an SFTP channel");
                }
            }
        }
        catch (error) {
            await this.#terminate(error);
        }
    }
    async #replenishReceiveWindow() {
        if (this.#closed || this.#normalClosing)
            return;
        const available = this.#controller.desiredSize;
        if (available === null)
            return;
        const queued = DEFAULT_SFTP_CHANNEL_WINDOW_SIZE - Math.max(0, available);
        const bytesToAdd = DEFAULT_SFTP_CHANNEL_WINDOW_SIZE - this.#receiveWindow - queued;
        if (bytesToAdd <= 0)
            return;
        this.#receiveWindow += bytesToAdd;
        try {
            await this.#io.writePayload(formatChannelWindowAdjust({ recipientChannel: this.#remoteChannel, bytesToAdd }));
        }
        catch (error) {
            await this.#terminate(error);
            throw error;
        }
    }
    async #write(chunk) {
        if (!(chunk instanceof Uint8Array))
            throw new SSHClientError("SFTP channel accepts only byte chunks");
        try {
            for (let offset = 0; offset < chunk.length;) {
                while (this.#remoteWindow === 0) {
                    if (this.#closed)
                        throw new SSHClientError("SFTP channel is closed");
                    await new Promise((resolve, reject) => this.#windowWaiters.push({ resolve, reject }));
                }
                const length = Math.min(chunk.length - offset, this.#remoteWindow, this.#remoteMaximumPacketSize);
                this.#remoteWindow -= length;
                await this.#io.writePayload(formatChannelData({ recipientChannel: this.#remoteChannel, data: chunk.subarray(offset, offset + length) }));
                offset += length;
            }
        }
        catch (error) {
            await this.#terminate(error);
            throw error;
        }
    }
    async #sendEof() {
        if (!this.#sentEof) {
            this.#sentEof = true;
            await this.#io.writePayload(formatChannelEof(this.#remoteChannel));
        }
    }
    async #sendClose() {
        if (!this.#sentClose) {
            this.#sentClose = true;
            await this.#io.writePayload(formatChannelClose(this.#remoteChannel));
        }
    }
    #completeNormalClose() {
        if (this.#closed)
            return;
        this.#closed = true;
        try {
            this.#controller.close();
        }
        catch {
            // The SFTP reader may already have cancelled this stream.
        }
        this.#release();
    }
    #terminate(reason) {
        if (!this.#terminal) {
            this.#closed = true;
            try {
                this.#controller.error(reason);
            }
            catch {
                // The SFTP reader may already have closed this stream.
            }
            this.#rejectRemoteClose(reason);
            for (const waiter of this.#windowWaiters.splice(0))
                waiter.reject(reason);
            this.#terminal = this.#io.shutdown(reason).finally(() => this.#release());
        }
        return this.#terminal;
    }
    #release() {
        if (!this.#released) {
            this.#released = true;
            this.#releaseLease();
        }
    }
}
class ByteBuffer {
    maximumPacketLength;
    #maximumLength;
    #maximumQueuedLength;
    #bytes;
    #start = 0;
    #length = 0;
    #queuedLength = 0;
    #queued = [];
    #queuedStart = 0;
    constructor(maximumPacketLength) {
        this.maximumPacketLength = maximumPacketLength;
        this.#maximumLength = Math.max(255, maximumPacketLength + 36);
        this.#maximumQueuedLength = this.#maximumLength * 2;
        this.#bytes = new Uint8Array(Math.min(1024, this.#maximumLength) * 2);
    }
    get bytes() {
        return this.#bytes.subarray(this.#start, this.#start + this.#length);
    }
    append(chunk) {
        if (chunk.length === 0)
            return;
        if (chunk.length > this.#maximumQueuedLength - this.#queuedLength)
            throw new SSHClientError("SSH receive queue exceeds the configured packet limit");
        this.#queued.push({ bytes: chunk, start: 0 });
        this.#queuedLength += chunk.length;
        this.#fill();
    }
    consume(length) {
        if (!Number.isSafeInteger(length) || length < 0 || length > this.#length)
            throw new SSHClientError("SSH packet consumed an invalid byte count");
        this.#start = (this.#start + length) % this.#capacity;
        this.#length -= length;
        if (this.#length === 0)
            this.#start = 0;
        this.#fill();
    }
    /** Makes queued bytes available without reading another stream chunk. */
    drain() {
        if (this.#queuedStart === this.#queued.length)
            return false;
        if (this.#length === this.#capacity)
            this.#grow();
        this.#fill();
        return true;
    }
    /** Reserves active-window capacity before accepting another stream chunk. */
    prepareForAppend() {
        if (this.#length === this.#capacity)
            this.#grow();
    }
    get #capacity() {
        return this.#bytes.length / 2;
    }
    #fill() {
        while (this.#queuedStart < this.#queued.length && this.#length < this.#capacity) {
            const chunk = this.#queued[this.#queuedStart];
            const available = this.#capacity - this.#length;
            const position = (this.#start + this.#length) % this.#capacity;
            const count = Math.min(available, this.#capacity - position, chunk.bytes.length - chunk.start);
            const source = chunk.bytes.subarray(chunk.start, chunk.start + count);
            this.#bytes.set(source, position);
            this.#bytes.set(source, position + this.#capacity);
            this.#length += count;
            chunk.start += count;
            this.#queuedLength -= count;
            if (chunk.start === chunk.bytes.length) {
                this.#queuedStart++;
                this.#discardConsumedChunks();
            }
        }
    }
    #discardConsumedChunks() {
        if (this.#queuedStart === this.#queued.length) {
            this.#queued = [];
            this.#queuedStart = 0;
        }
        else if (this.#queuedStart >= 1024 && this.#queuedStart * 2 >= this.#queued.length) {
            this.#queued = this.#queued.slice(this.#queuedStart);
            this.#queuedStart = 0;
        }
    }
    #grow() {
        if (this.#capacity === this.#maximumLength)
            throw new SSHClientError("SSH receive buffer exceeds the configured packet limit");
        const capacity = Math.min(this.#maximumLength, this.#capacity * 2);
        const expanded = new Uint8Array(capacity * 2);
        const bytes = this.bytes;
        expanded.set(bytes);
        expanded.set(bytes, capacity);
        this.#bytes = expanded;
        this.#start = 0;
    }
}
function createKexInit() {
    const cookie = new Uint8Array(16);
    crypto.getRandomValues(cookie);
    return {
        cookie,
        kexAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"],
        languagesClientToServer: [],
        languagesServerToClient: [],
        firstKexPacketFollows: false,
    };
}
async function readPeerIdentification(io) {
    while (true) {
        const result = readIdentification(io.bytes);
        if (result) {
            io.consume(result.consumed);
            const { protocolVersion, softwareVersion, comments } = result.identification;
            return `SSH-${protocolVersion}-${softwareVersion}${comments === undefined ? "" : ` ${comments}`}`;
        }
        await io.readMore();
    }
}
function freezeAlgorithms(selection) {
    return Object.freeze({ ...selection });
}
function validateOptions(options) {
    if (!options || typeof options !== "object")
        throw new SSHClientError("SSH connect options are required");
    const transport = options.transport;
    if (!transport || typeof transport !== "object" || !isReadableStream(transport.readable) ||
        !isWritableStream(transport.writable)) {
        throw new SSHClientError("SSH transport must provide readable and writable byte streams");
    }
    if (transport.close !== undefined && typeof transport.close !== "function")
        throw new SSHClientError("SSH transport close must be a function");
    if (!options.host || typeof options.host !== "object" || typeof options.host.hostname !== "string" ||
        !options.host.hostname) {
        throw new SSHClientError("SSH host hostname must be a non-empty string");
    }
    if (options.host.hostname.includes("\0"))
        throw new SSHClientError("SSH host hostname must not contain NUL");
    const port = options.host.port ?? 22;
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
        throw new SSHClientError("SSH host port must be an integer between 1 and 65535");
    if (typeof options.username !== "string" || !options.username || options.username.includes("\0"))
        throw new SSHClientError("SSH username must be a non-empty string without NUL");
    if (!options.hostVerifier || typeof options.hostVerifier.verify !== "function")
        throw new SSHClientError("SSH hostVerifier.verify is required");
    if (!options.credential || !(options.credential.publicKey instanceof SSHPublicKey) ||
        options.credential.publicKey.type !== "ssh-ed25519")
        throw new SSHClientError("an ssh-ed25519 public-key credential is required");
    if (options.credential.privateKey?.type !== "private" || options.credential.privateKey.algorithm.name !== "Ed25519") {
        throw new SSHClientError("an Ed25519 private-key credential is required");
    }
    if (options.signal !== undefined && !(options.signal instanceof AbortSignal))
        throw new SSHClientError("SSH signal must be an AbortSignal");
    const maximumPacketLength = options.maximumPacketLength ?? DEFAULT_MAXIMUM_PACKET_LENGTH;
    if (!Number.isSafeInteger(maximumPacketLength) || maximumPacketLength < 5 || maximumPacketLength > 0xffff_ffff) {
        throw new SSHClientError("maximum SSH packet length must be an integer between 5 and 2^32 - 1");
    }
    const softwareVersion = options.softwareVersion ?? DEFAULT_SOFTWARE_VERSION;
    try {
        formatIdentification({ protocolVersion: "2.0", softwareVersion });
    }
    catch (error) {
        throw new SSHClientError("SSH softwareVersion is invalid", { cause: error });
    }
    return { ...options, transport, hostname: options.host.hostname, port, maximumPacketLength, softwareVersion };
}
function validateRunOptions(command, options) {
    if (typeof command !== "string")
        throw new SSHClientError("SSH command must be a string");
    // The connection codec owns SSH string encoding and rejects NUL commands.
    try {
        formatExecChannelRequest({ recipientChannel: 0, wantReply: true, command });
    }
    catch (error) {
        throw new SSHClientError("SSH command must be valid UTF-8 without NUL", { cause: error });
    }
    if (options !== undefined && (!options || typeof options !== "object"))
        throw new SSHClientError("SSH run options must be an object");
    if (options?.signal !== undefined && !(options.signal instanceof AbortSignal))
        throw new SSHClientError("SSH run signal must be an AbortSignal");
    const maximumOutputBytes = options?.maximumOutputBytes ?? DEFAULT_MAXIMUM_OUTPUT_BYTES;
    if (!Number.isSafeInteger(maximumOutputBytes) || maximumOutputBytes < 1 || maximumOutputBytes > 0xffff_ffff) {
        throw new SSHClientError("maximum SSH command output must be an integer between 1 and 2^32 - 1");
    }
    return { signal: options?.signal, maximumOutputBytes };
}
function validateOpenSftpOptions(options) {
    if (options !== undefined && (!options || typeof options !== "object"))
        throw new SSHClientError("SSH SFTP options must be an object");
    if (options?.signal !== undefined && !(options.signal instanceof AbortSignal))
        throw new SSHClientError("SSH SFTP signal must be an AbortSignal");
    for (const [name, value] of [
        ["maximum SFTP packet length", options?.maximumPacketLength],
        ["maximum SFTP pending requests", options?.maximumPendingRequests],
    ]) {
        if (value !== undefined && (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff))
            throw new SSHClientError(`${name} must be an integer between 1 and 2^32 - 1`);
    }
    return options ?? {};
}
function validateConnectTcpOptions(host, port, options) {
    if (typeof host !== "string" || !host)
        throw new SSHClientError("TCP host must be a non-empty string");
    if (host.includes("\0"))
        throw new SSHClientError("TCP host must not contain NUL");
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
        throw new SSHClientError("TCP port must be an integer between 1 and 65535");
    if (!options || typeof options !== "object")
        throw new SSHClientError("TCP connection options must be an object");
    if (options.signal !== undefined && !(options.signal instanceof AbortSignal))
        throw new SSHClientError("TCP signal must be an AbortSignal");
    return options.signal;
}
function getDenoTcp() {
    const deno = globalThis.Deno;
    if (!deno || typeof deno !== "object" || !("connect" in deno) || typeof deno.connect !== "function")
        return undefined;
    return deno;
}
function getNodeNet() {
    const process = globalThis.process;
    const net = process?.getBuiltinModule?.("node:net");
    if (!net || typeof net !== "object" || !("createConnection" in net) || typeof net.createConnection !== "function")
        return undefined;
    return net;
}
async function connectWithAbort(open, close, signal) {
    if (!signal)
        return await open();
    throwIfAborted(signal);
    return await new Promise((resolve, reject) => {
        let settled = false;
        const abort = () => {
            if (settled)
                return;
            settled = true;
            signal.removeEventListener("abort", abort);
            reject(abortError(signal));
        };
        signal.addEventListener("abort", abort, { once: true });
        let connecting;
        try {
            connecting = open();
        }
        catch (error) {
            settled = true;
            signal.removeEventListener("abort", abort);
            reject(error);
            return;
        }
        void connecting.then((value) => {
            if (settled) {
                try {
                    close(value);
                }
                catch { /* The aborted connection is already being discarded. */ }
                return;
            }
            settled = true;
            signal.removeEventListener("abort", abort);
            resolve(value);
        }, (error) => {
            if (settled)
                return;
            settled = true;
            signal.removeEventListener("abort", abort);
            reject(error);
        });
    });
}
function denoTransport(connection) {
    let closed = false;
    return {
        readable: connection.readable,
        writable: connection.writable,
        close() {
            if (closed)
                return;
            closed = true;
            connection.close();
        },
    };
}
async function connectNodeTcp(net, host, port, signal) {
    if (signal)
        throwIfAborted(signal);
    let socket;
    try {
        socket = net.createConnection({ host, port });
    }
    catch (error) {
        throw asClientError(error);
    }
    await new Promise((resolve, reject) => {
        let settled = false;
        const cleanup = () => {
            socket.removeListener("connect", connected);
            socket.removeListener("error", failed);
            signal?.removeEventListener("abort", aborted);
        };
        const connected = () => {
            if (settled)
                return;
            settled = true;
            cleanup();
            resolve();
        };
        const failed = (error) => {
            if (settled)
                return;
            settled = true;
            cleanup();
            socket.destroy();
            reject(error);
        };
        const aborted = () => {
            if (settled)
                return;
            settled = true;
            cleanup();
            socket.destroy();
            reject(abortError(signal));
        };
        socket.once("connect", connected);
        socket.once("error", failed);
        signal?.addEventListener("abort", aborted, { once: true });
        if (signal?.aborted)
            aborted();
    });
    return nodeTransport(socket);
}
function nodeTransport(socket) {
    let closed = false;
    const close = () => {
        if (closed)
            return;
        closed = true;
        socket.destroy();
    };
    const iterator = socket[Symbol.asyncIterator]();
    return {
        readable: new ReadableStream({
            async pull(controller) {
                try {
                    const result = await iterator.next();
                    if (result.done) {
                        controller.close();
                        return;
                    }
                    if (!(result.value instanceof Uint8Array))
                        throw new SSHClientError("TCP socket produced a non-byte chunk");
                    // Copy Buffer instances so the public stream never exposes Node-specific byte values.
                    controller.enqueue(new Uint8Array(result.value));
                }
                catch (error) {
                    controller.error(asClientError(error));
                }
            },
            async cancel() {
                close();
                await iterator.return?.();
            },
        }, { highWaterMark: 1 }),
        writable: new WritableStream({
            write(chunk) {
                if (!(chunk instanceof Uint8Array))
                    return Promise.reject(new SSHClientError("TCP socket accepts only byte chunks"));
                return new Promise((resolve, reject) => {
                    try {
                        socket.write(chunk, (error) => error === undefined || error === null ? resolve() : reject(asClientError(error)));
                    }
                    catch (error) {
                        reject(asClientError(error));
                    }
                });
            },
            close,
            abort: close,
        }),
        close,
    };
}
function joinOutput(chunks) {
    const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
    const output = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
        output.set(chunk, offset);
        offset += chunk.length;
    }
    return output;
}
function isReadableStream(value) {
    return typeof value === "object" && value !== null && "getReader" in value &&
        typeof value.getReader === "function";
}
function isWritableStream(value) {
    return typeof value === "object" && value !== null && "getWriter" in value &&
        typeof value.getWriter === "function";
}
function throwIfAborted(signal) {
    if (signal.aborted)
        throw abortError(signal);
}
function abortError(signal) {
    return new SSHClientError("SSH connection aborted", { cause: signal.reason });
}
function asClientError(error) {
    if (error instanceof SSHClientError)
        return error;
    return new SSHClientError("SSH connection failed", { cause: error });
}
