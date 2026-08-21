import { formatServiceRequest, formatSignedEd25519UserAuthRequest, parseServiceAccept, parseUserAuthSuccess, } from "./auth.js";
import { createAes128CtrHmacSha256Cipher } from "./cipher.js";
import { formatIdentification, readIdentification } from "./identification.js";
import { formatKexEcdhInit, formatKexInit, formatNewKeys, generateX25519KeyPair, isKexGuessCorrect, negotiateKexInit, parseKexEcdhReply, parseKexInit, parseNewKeys, verifyCurve25519Sha256Reply, } from "./kex.js";
import { formatPacket, readPacket } from "./packet.js";
import { SSHPublicKey } from "./public_key.js";
import { formatChannelClose, formatChannelData, formatChannelEof, formatChannelWindowAdjust, formatExecChannelRequest, formatGlobalRequestFailure, formatSessionChannelOpen, formatSubsystemChannelRequest, parseChannelClose, parseChannelData, parseChannelEof, parseChannelExtendedData, parseChannelOpenConfirmation, parseChannelOpenFailure, parseChannelRequest, parseChannelRequestFailure, parseChannelRequestSuccess, parseChannelWindowAdjust, parseExitStatus, parseGlobalRequest, } from "./connection.js";
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
const MAXIMUM_MANAGED_CHANNELS = 64;
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
 * A client owns its transport after connecting. A private multiplexer continuously routes post-authentication
 * traffic to up to 64 managed command and SFTP channels.
 */
export class SshClient {
    connectionInfo;
    #mux;
    constructor(io, connectionInfo) {
        this.#mux = new ChannelMux(io);
        this.connectionInfo = connectionInfo;
    }
    /** Creates an owning client after its handshake has completed. @internal */
    static create(io, connectionInfo) {
        return new SshClient(io, connectionInfo);
    }
    /** Immediately terminates the owned transport and rejects any pending command. */
    close(reason) {
        return this.#mux.close(reason);
    }
    /** Immediately aborts the owned transport. */
    abort(reason) {
        return this.#mux.close(reason);
    }
    /** Immediately starts best-effort transport termination without waiting for cleanup. */
    dispose(reason) {
        void this.abort(reason);
    }
    /** Immediately starts best-effort transport termination without waiting for cleanup. */
    [Symbol.dispose]() {
        this.dispose();
    }
    /** Immediately terminates the owned transport. */
    [Symbol.asyncDispose]() {
        return this.close();
    }
    /**
     * Runs one bounded remote `exec` command on an owned `session` channel.
     *
     * Commands may run concurrently, up to the managed-channel limit. The result resolves after remote EOF,
     * close, and `exit-status`; a nonzero exit status is result data. Stdout and stderr share
     * `maximumOutputBytes`, which defaults to 1 MiB. Cancelling after opening has started closes only this
     * channel and rejects this command. Calling `close()` rejects every active child operation.
     */
    run(command, options) {
        if (this.#mux.isClosed)
            return Promise.reject(new SSHClientError("SSH client is closed"));
        return this.#run(command, options);
    }
    /**
     * Opens one managed SFTP v3 subsystem channel.
     *
     * Commands and SFTP subsystems may coexist, up to the managed-channel limit. Closing the returned SFTP
     * client closes only its subsystem channel. Aborting after channel opening starts closes only this channel.
     */
    openSftp(options) {
        if (this.#mux.isClosed)
            return Promise.reject(new SSHClientError("SSH client is closed"));
        return this.#openSftp(options);
    }
    async #openSftp(options) {
        const validated = validateOpenSftpOptions(options);
        if (validated.signal)
            throwIfAborted(validated.signal);
        const channel = this.#mux.createSftp();
        let abortListener;
        try {
            if (validated.signal) {
                abortListener = () => channel.cancel(abortError(validated.signal));
                validated.signal.addEventListener("abort", abortListener, { once: true });
            }
            await channel.start();
            return await SFTPClient.connect(channel, validated);
        }
        catch (error) {
            await channel.close(error);
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
        if (signal)
            throwIfAborted(signal);
        const channel = this.#mux.createCommand(maximumOutputBytes);
        let abortListener;
        try {
            if (signal) {
                abortListener = () => channel.cancel(abortError(signal));
                signal.addEventListener("abort", abortListener, { once: true });
            }
            return await channel.start(command);
        }
        catch (error) {
            if (signal?.aborted)
                throw abortError(signal);
            throw asClientError(error);
        }
        finally {
            if (signal && abortListener)
                signal.removeEventListener("abort", abortListener);
        }
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
/** The only post-authentication packet reader and owner of managed channel IDs. */
class ChannelMux {
    #io;
    #channels = new Map();
    #nextLocalChannel = 0;
    #terminal;
    constructor(io) {
        this.#io = io;
        void this.#readLoop();
    }
    get isClosed() {
        return this.#terminal !== undefined || this.#io.isShutdown;
    }
    createCommand(maximumOutputBytes) {
        return this.#register(new ManagedCommandChannel(this, this.#allocate(), maximumOutputBytes));
    }
    createSftp() {
        return this.#register(new ManagedSftpChannel(this, this.#allocate()));
    }
    close(reason) {
        return this.#fatal(reason ?? new SSHClientError("SSH client is closed"));
    }
    async write(payload) {
        if (this.#terminal)
            throw new SSHClientError("SSH client is closed");
        try {
            await this.#io.writePayload(payload);
        }
        catch (error) {
            await this.#fatal(error);
            throw error;
        }
    }
    release(channel) {
        if (this.#channels.get(channel.localChannel) === channel)
            this.#channels.delete(channel.localChannel);
    }
    #register(channel) {
        this.#channels.set(channel.localChannel, channel);
        return channel;
    }
    #allocate() {
        if (this.#channels.size >= MAXIMUM_MANAGED_CHANNELS)
            throw new SSHClientError(`SSH managed channel limit of ${MAXIMUM_MANAGED_CHANNELS} reached`);
        if (this.#nextLocalChannel > 0xffff_ffff)
            throw new SSHClientError("SSH local channel ID space is exhausted");
        return this.#nextLocalChannel++;
    }
    async #readLoop() {
        try {
            while (true)
                await this.#route(await this.#io.readPayload());
        }
        catch (error) {
            await this.#fatal(error);
        }
    }
    async #route(payload) {
        switch (payload[0]) {
            case 2: // SSH_MSG_IGNORE
            case 4: // SSH_MSG_DEBUG
                return;
            case 80: {
                const request = parseGlobalRequest(payload);
                if (request.wantReply)
                    await this.write(formatGlobalRequestFailure());
                return;
            }
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                return await this.#channel(parseChannelOpenConfirmation(payload).recipientChannel).confirmation(payload);
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                return await this.#channel(parseChannelOpenFailure(payload).recipientChannel).openFailure(payload);
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                return await this.#channel(parseChannelWindowAdjust(payload).recipientChannel).windowAdjust(payload);
            case SSH_MSG_CHANNEL_DATA:
                return await this.#channel(parseChannelData(payload).recipientChannel).data(payload);
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                return await this.#channel(parseChannelExtendedData(payload).recipientChannel).extendedData(payload);
            case SSH_MSG_CHANNEL_EOF:
                return await this.#channel(parseChannelEof(payload)).eof();
            case SSH_MSG_CHANNEL_CLOSE:
                return await this.#channel(parseChannelClose(payload)).closeReceived();
            case SSH_MSG_CHANNEL_REQUEST:
                return await this.#channel(parseChannelRequest(payload).recipientChannel).request(payload);
            case SSH_MSG_CHANNEL_SUCCESS:
                return this.#channel(parseChannelRequestSuccess(payload)).requestReply(true);
            case SSH_MSG_CHANNEL_FAILURE:
                return this.#channel(parseChannelRequestFailure(payload)).requestReply(false);
            case 20:
                throw new SSHClientError("SSH rekeying is unsupported");
            case 81:
            case 82:
            case 90:
                throw new SSHClientError("received an unsolicited or unsupported SSH connection message");
            default:
                throw new SSHClientError("received an unexpected post-authentication SSH message");
        }
    }
    #channel(localChannel) {
        const channel = this.#channels.get(localChannel);
        if (!channel)
            throw new SSHClientError("SSH message addressed an unknown channel");
        return channel;
    }
    #fatal(reason) {
        if (!this.#terminal) {
            const error = asClientError(reason);
            for (const channel of this.#channels.values())
                channel.terminal(error);
            this.#channels.clear();
            this.#terminal = this.#io.shutdown(error);
        }
        return this.#terminal;
    }
}
class ManagedChannel {
    localChannel;
    mux;
    remoteChannel;
    remoteWindow = 0;
    remoteMaximumPacketSize = 0;
    receivedEof = false;
    closing = false;
    #openedResolve;
    #openedReject;
    #opened = new Promise((resolve, reject) => {
        this.#openedResolve = resolve;
        this.#openedReject = reject;
    });
    #reply;
    #sentEof = false;
    #sentClose = false;
    #receivedClose = false;
    constructor(mux, localChannel) {
        this.mux = mux;
        this.localChannel = localChannel;
    }
    async open(initialWindowSize) {
        await this.mux.write(formatSessionChannelOpen({
            senderChannel: this.localChannel,
            initialWindowSize,
            maximumPacketSize: DEFAULT_CHANNEL_MAXIMUM_PACKET_SIZE,
        }));
        await this.#opened;
    }
    async sendRequest(payload) {
        if (this.#reply)
            throw new SSHClientError("SSH channel already has a request awaiting a reply");
        const reply = new Promise((resolve, reject) => this.#reply = { resolve, reject });
        await this.mux.write(payload);
        await reply;
    }
    async sendEof() {
        if (this.remoteChannel === undefined)
            throw new SSHClientError("SSH channel has not opened");
        if (!this.#sentEof) {
            this.#sentEof = true;
            await this.mux.write(formatChannelEof(this.remoteChannel));
        }
    }
    async close(_reason) {
        this.closing = true;
        if (this.remoteChannel !== undefined)
            await this.#sendClose();
    }
    async confirmation(payload) {
        if (this.remoteChannel !== undefined || this.#receivedClose)
            throw new SSHClientError("SSH channel opened more than once");
        const confirmation = parseChannelOpenConfirmation(payload);
        this.remoteChannel = confirmation.senderChannel;
        this.remoteWindow = confirmation.initialWindowSize;
        this.remoteMaximumPacketSize = confirmation.maximumPacketSize;
        this.#openedResolve();
        if (this.closing)
            await this.#sendClose();
    }
    openFailure(payload) {
        if (this.remoteChannel !== undefined)
            throw new SSHClientError("SSH channel failed after opening");
        parseChannelOpenFailure(payload);
        const error = new SSHClientError("SSH server rejected the session channel");
        this.#openedReject(error);
        this.onTerminal(error);
        this.mux.release(this);
    }
    requestReply(success) {
        const reply = this.#reply;
        if (!reply)
            throw new SSHClientError("SSH channel sent an unsolicited request reply");
        this.#reply = undefined;
        if (success)
            reply.resolve();
        else
            reply.reject(new SSHClientError("SSH server rejected a channel request"));
    }
    async eof() {
        if (this.receivedEof || this.#receivedClose)
            throw new SSHClientError("SSH channel sent EOF after closing");
        this.receivedEof = true;
        await this.onEof();
    }
    async closeReceived() {
        if (this.#receivedClose)
            throw new SSHClientError("SSH channel sent close more than once");
        this.#receivedClose = true;
        if (!this.#sentClose)
            await this.#sendClose();
        try {
            await this.onClose();
        }
        catch (error) {
            this.onTerminal(error);
            throw error;
        }
        finally {
            this.mux.release(this);
        }
    }
    terminal(reason) {
        this.#openedReject(reason);
        this.#reply?.reject(reason);
        this.#reply = undefined;
        this.onTerminal(reason);
    }
    async #sendClose() {
        if (this.remoteChannel === undefined || this.#sentClose)
            return;
        this.#sentClose = true;
        await this.mux.write(formatChannelClose(this.remoteChannel));
    }
}
class ManagedCommandChannel extends ManagedChannel {
    #maximumOutputBytes;
    #result;
    #resolveResult;
    #rejectResult;
    #stdout = [];
    #stderr = [];
    #outputLength = 0;
    #receiveWindow;
    #exitCode;
    #cancelled;
    #settled = false;
    constructor(mux, localChannel, maximumOutputBytes) {
        super(mux, localChannel);
        this.#maximumOutputBytes = maximumOutputBytes;
        this.#receiveWindow = Math.min(maximumOutputBytes, DEFAULT_CHANNEL_WINDOW_SIZE);
        this.#result = new Promise((resolve, reject) => {
            this.#resolveResult = resolve;
            this.#rejectResult = reject;
        });
    }
    start(command) {
        void this.#begin(command);
        return this.#result;
    }
    cancel(reason) {
        if (!this.#cancelled) {
            this.#cancelled = reason;
            this.#reject(reason);
            void this.close(reason).catch(() => undefined);
        }
    }
    async windowAdjust(_payload) {
        throw new SSHClientError("SSH command channel received an unexpected window adjustment");
    }
    async data(payload) {
        if (this.closing || this.receivedEof)
            throw new SSHRemoteExitError("SSH channel sent data after EOF or close");
        try {
            await this.#append(this.#stdout, parseChannelData(payload).data);
        }
        catch (error) {
            this.#reject(error);
            await this.close(error);
        }
    }
    async extendedData(payload) {
        if (this.closing || this.receivedEof)
            throw new SSHRemoteExitError("SSH channel sent data after EOF or close");
        try {
            const data = parseChannelExtendedData(payload);
            if (data.dataTypeCode !== 1)
                throw new SSHClientError("SSH channel sent an unsupported extended-data type");
            await this.#append(this.#stderr, data.data);
        }
        catch (error) {
            this.#reject(error);
            await this.close(error);
        }
    }
    async request(payload) {
        const status = parseExitStatus(payload);
        if (this.#exitCode !== undefined)
            throw new SSHRemoteExitError("SSH channel sent more than one exit status");
        this.#exitCode = status.status;
    }
    async onEof() {
        return;
    }
    async onClose() {
        if (this.#cancelled)
            return;
        if (!this.receivedEof)
            throw new SSHRemoteExitError("SSH channel closed before EOF");
        if (this.#exitCode === undefined)
            throw new SSHRemoteExitError("SSH command ended without an exit status");
        this.#resolve(Object.freeze({
            stdout: joinOutput(this.#stdout),
            stderr: joinOutput(this.#stderr),
            exitCode: this.#exitCode,
        }));
    }
    onTerminal(reason) {
        this.#reject(reason);
    }
    async #begin(command) {
        try {
            await this.open(this.#receiveWindow);
            if (this.#cancelled)
                return;
            await this.sendRequest(formatExecChannelRequest({
                recipientChannel: this.remoteChannel,
                wantReply: true,
                command,
            }));
            if (this.#cancelled)
                return;
            await this.sendEof();
        }
        catch (error) {
            if (!this.#cancelled) {
                this.#reject(error);
                await this.close(error);
            }
        }
    }
    async #append(output, data) {
        if (this.closing || this.receivedEof)
            throw new SSHRemoteExitError("SSH channel sent data after EOF or close");
        if (data.length > this.#receiveWindow)
            throw new SSHClientError("SSH channel exceeded its receive window");
        if (data.length > this.#maximumOutputBytes - this.#outputLength)
            throw new SSHClientError("SSH command output exceeds the configured limit");
        this.#receiveWindow -= data.length;
        if (data.length > 0)
            output.push(data.slice());
        if (data.length > 0 && this.remoteChannel !== undefined) {
            await this.mux.write(formatChannelWindowAdjust({ recipientChannel: this.remoteChannel, bytesToAdd: data.length }));
            this.#receiveWindow += data.length;
        }
        this.#outputLength += data.length;
    }
    #resolve(result) {
        if (!this.#settled) {
            this.#settled = true;
            this.#resolveResult(result);
        }
    }
    #reject(reason) {
        if (!this.#settled) {
            this.#settled = true;
            this.#rejectResult(reason);
        }
    }
}
/** Private SFTP stream bridge fed by the channel multiplexer. */
class ManagedSftpChannel extends ManagedChannel {
    readable;
    writable;
    #ready;
    #remoteClose;
    #resolveReady;
    #rejectReady;
    #resolveRemoteClose;
    #rejectRemoteClose;
    #controller;
    #receiveWindow = DEFAULT_SFTP_CHANNEL_WINDOW_SIZE;
    #normalClosing = false;
    #closed = false;
    #cancelled;
    #windowWaiters = [];
    constructor(mux, localChannel) {
        super(mux, localChannel);
        this.#ready = new Promise((resolve, reject) => {
            this.#resolveReady = resolve;
            this.#rejectReady = reject;
        });
        this.#remoteClose = new Promise((resolve, reject) => {
            this.#resolveRemoteClose = resolve;
            this.#rejectRemoteClose = reject;
        });
        void this.#remoteClose.catch(() => undefined);
        this.readable = new ReadableStream({
            start: (controller) => this.#controller = controller,
            pull: () => this.#replenishReceiveWindow(),
            cancel: (reason) => this.close(reason),
        }, { highWaterMark: DEFAULT_SFTP_CHANNEL_WINDOW_SIZE, size: (chunk) => chunk.length });
        this.writable = new WritableStream({
            write: (chunk) => this.#write(chunk),
            close: () => this.close(),
            abort: (reason) => this.close(reason),
        });
    }
    start() {
        void this.#begin();
        return this.#ready;
    }
    cancel(reason) {
        if (!this.#cancelled) {
            this.#cancelled = reason;
            this.#rejectReady(reason);
            void this.close(reason).catch(() => undefined);
        }
    }
    async close(_reason) {
        if (this.#closed)
            return;
        this.#normalClosing = true;
        this.closing = true;
        try {
            if (this.remoteChannel === undefined)
                return await super.close();
            await this.sendEof();
            await super.close();
            await this.#remoteClose;
        }
        catch (error) {
            this.onTerminal(error);
            throw error;
        }
    }
    async windowAdjust(payload) {
        const adjust = parseChannelWindowAdjust(payload);
        if (adjust.bytesToAdd > 0xffff_ffff - this.remoteWindow)
            throw new SSHClientError("SSH SFTP channel window exceeds its maximum");
        this.remoteWindow += adjust.bytesToAdd;
        for (const waiter of this.#windowWaiters.splice(0))
            waiter.resolve();
    }
    async data(payload) {
        if (this.#normalClosing)
            throw new SSHClientError("SSH SFTP channel sent data while closing");
        const data = parseChannelData(payload).data;
        if (data.length > this.#receiveWindow)
            throw new SSHClientError("SSH SFTP channel exceeded its receive window");
        const available = this.#controller.desiredSize;
        if (available === null || data.length > available)
            throw new SSHClientError("SSH SFTP channel exceeded its bounded receive queue");
        this.#receiveWindow -= data.length;
        if (data.length > 0)
            this.#controller.enqueue(data.slice());
    }
    async extendedData(_payload) {
        throw new SSHClientError("SSH SFTP channel received extended data");
    }
    async request(_payload) {
        throw new SSHClientError("SSH SFTP channel received an unexpected request");
    }
    async onEof() {
        if (!this.#normalClosing)
            throw new SSHClientError("SSH SFTP channel ended unexpectedly");
    }
    async onClose() {
        if (!this.#normalClosing)
            throw new SSHClientError("SSH SFTP channel closed unexpectedly");
        this.#closed = true;
        try {
            this.#controller.close();
        }
        catch {
            // The SFTP reader may already have cancelled this stream.
        }
        this.#resolveRemoteClose();
    }
    onTerminal(reason) {
        this.#closed = true;
        this.#rejectReady(reason);
        this.#rejectRemoteClose(reason);
        for (const waiter of this.#windowWaiters.splice(0))
            waiter.reject(reason);
        try {
            this.#controller.error(reason);
        }
        catch {
            // The SFTP reader may already have closed this stream.
        }
    }
    async #begin() {
        try {
            await this.open(DEFAULT_SFTP_CHANNEL_WINDOW_SIZE);
            if (this.#cancelled)
                return;
            await this.sendRequest(formatSubsystemChannelRequest({
                recipientChannel: this.remoteChannel,
                wantReply: true,
                subsystem: "sftp",
            }));
            if (!this.#cancelled)
                this.#resolveReady();
        }
        catch (error) {
            if (!this.#cancelled) {
                this.#rejectReady(error);
                await this.close(error);
            }
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
        if (bytesToAdd <= 0 || this.remoteChannel === undefined)
            return;
        this.#receiveWindow += bytesToAdd;
        await this.mux.write(formatChannelWindowAdjust({ recipientChannel: this.remoteChannel, bytesToAdd }));
    }
    async #write(chunk) {
        if (!(chunk instanceof Uint8Array))
            throw new SSHClientError("SFTP channel accepts only byte chunks");
        try {
            for (let offset = 0; offset < chunk.length;) {
                while (this.remoteWindow === 0) {
                    if (this.#closed || this.closing)
                        throw new SSHClientError("SFTP channel is closed");
                    await new Promise((resolve, reject) => this.#windowWaiters.push({ resolve, reject }));
                }
                const length = Math.min(chunk.length - offset, this.remoteWindow, this.remoteMaximumPacketSize);
                this.remoteWindow -= length;
                await this.mux.write(formatChannelData({
                    recipientChannel: this.remoteChannel,
                    data: chunk.subarray(offset, offset + length),
                }));
                offset += length;
            }
        }
        catch (error) {
            void this.close(error).catch(() => undefined);
            throw error;
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
