import {
  formatSftpCloseRequest,
  formatSftpInit,
  formatSftpOpenDirRequest,
  formatSftpOpenRequest,
  formatSftpReadDirRequest,
  formatSftpReadRequest,
  formatSftpStatRequest,
  formatSftpWriteRequest,
  parseSftpAttributes,
  parseSftpData,
  parseSftpHandle,
  parseSftpName,
  parseSftpStatus,
  parseSftpVersion,
  readSftpPacket,
  type SFTPAttributes as RawAttributes,
  type SFTPNameEntry as RawNameEntry,
} from "./protocol/sftp.ts";

const SSH_FXP_VERSION = 2;
const SSH_FXP_HANDLE = 102;
const SSH_FXP_DATA = 103;
const SSH_FXP_NAME = 104;
const SSH_FXP_ATTRS = 105;
const SSH_FXP_STATUS = 101;
const SSH_FX_OK = 0;
const SSH_FX_EOF = 1;
const SSH_FXF_READ = 0x0000_0001;
const SSH_FXF_WRITE = 0x0000_0002;
const SSH_FXF_CREAT = 0x0000_0008;
const SSH_FXF_TRUNC = 0x0000_0010;
const DEFAULT_MAXIMUM_PACKET_LENGTH = 1024 * 1024;
const DEFAULT_MAXIMUM_PENDING_REQUESTS = 64;
const MAXIMUM_CHUNK_LENGTH = 32 * 1024;

/** A byte-stream SSH subsystem channel suitable for SFTP. */
export type SFTPChannel = {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close?: (reason?: unknown) => void | Promise<void>;
};

/** SFTP server extension metadata. */
export type SFTPExtension = {
  readonly name: string;
  readonly data: Uint8Array;
};

/** SFTP v3 file metadata. */
export type SFTPAttributes = {
  readonly size?: bigint;
  readonly uid?: number;
  readonly gid?: number;
  readonly permissions?: number;
  readonly atime?: number;
  readonly mtime?: number;
  readonly extended?: readonly { readonly type: string; readonly data: Uint8Array }[];
};

/** One entry returned by {@link SFTPClient.readDir}. */
export type SFTPDirectoryEntry = {
  readonly filename: string;
  readonly longname: string;
  readonly attributes: SFTPAttributes;
};

/** Options for {@link SFTPClient.connect}. */
export type SFTPConnectOptions = {
  signal?: AbortSignal;
  maximumPacketLength?: number;
  maximumPendingRequests?: number;
};

/** Options for a streaming upload. */
export type SFTPUploadOptions = {
  create?: boolean;
  truncate?: boolean;
  signal?: AbortSignal;
};

/** Options for operations that can be cancelled. */
export type SFTPOperationOptions = {
  signal?: AbortSignal;
};

/** An SFTP status response other than SSH_FX_OK. */
export class SFTPStatusError extends Error {
  readonly code: number;
  readonly languageTag: string;

  constructor(code: number, message: string, languageTag: string) {
    super(message || `SFTP request failed with status ${code}`);
    this.name = "SFTPStatusError";
    this.code = code;
    this.languageTag = languageTag;
  }
}

type Response =
  | { type: "handle"; handle: Uint8Array }
  | { type: "data"; data: Uint8Array }
  | { type: "name"; entries: readonly RawNameEntry[] }
  | { type: "attributes"; attributes: RawAttributes }
  | { type: "status"; code: number; message: string; languageTag: string };

type Pending = {
  resolve: (response: Response) => void;
  reject: (reason: unknown) => void;
  signal?: AbortSignal;
  abort?: () => void;
  sent: boolean;
  terminateOnAbort: boolean;
};

/** A promise- and Web-stream-based SFTP v3 client over an existing subsystem channel. */
export class SFTPClient {
  readonly version = 3;

  readonly #channel: SFTPChannel;
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>;
  readonly #writer: WritableStreamDefaultWriter<Uint8Array>;
  readonly #maximumPacketLength: number;
  readonly #maximumPendingRequests: number;
  readonly #pending = new Map<number, Pending>();
  readonly #header = new Uint8Array(4);
  #headerLength = 0;
  #frame?: Uint8Array;
  #frameLength = 0;
  #extensions: readonly SFTPExtension[] = [];
  #nextId = 1;
  #closed = false;
  #terminalReason?: unknown;
  #shutdown?: Promise<void>;
  #awaitingVersion = true;
  #readerReleased = false;
  #writerReleased = false;
  #versionResolve!: (extensions: readonly SFTPExtension[]) => void;
  #versionReject!: (reason: unknown) => void;
  readonly #negotiated: Promise<readonly SFTPExtension[]>;

  private constructor(
    channel: SFTPChannel,
    reader: ReadableStreamDefaultReader<Uint8Array>,
    writer: WritableStreamDefaultWriter<Uint8Array>,
    maximumPacketLength: number,
    maximumPendingRequests: number,
  ) {
    this.#channel = channel;
    this.#reader = reader;
    this.#writer = writer;
    this.#maximumPacketLength = maximumPacketLength;
    this.#maximumPendingRequests = maximumPendingRequests;
    this.#negotiated = new Promise((resolve, reject) => {
      this.#versionResolve = resolve;
      this.#versionReject = reject;
    });
    void this.#readLoop();
  }

  /** Extensions advertised by the server during version negotiation. */
  get extensions(): readonly SFTPExtension[] {
    return this.#extensions.map((extension) => Object.freeze({ name: extension.name, data: extension.data.slice() }));
  }

  /**
   * Negotiates SFTP v3 and takes ownership of the established subsystem channel
   * once its stream locks are acquired.
   */
  static async connect(channel: SFTPChannel, options: SFTPConnectOptions = {}): Promise<SFTPClient> {
    const maximumPacketLength = options.maximumPacketLength ?? DEFAULT_MAXIMUM_PACKET_LENGTH;
    const maximumPendingRequests = options.maximumPendingRequests ?? DEFAULT_MAXIMUM_PENDING_REQUESTS;
    validateMaximumPacketLength(maximumPacketLength);
    validateMaximumPendingRequests(maximumPendingRequests);
    throwIfAborted(options.signal);

    const reader = channel.readable.getReader();
    let writer: WritableStreamDefaultWriter<Uint8Array>;
    try {
      writer = channel.writable.getWriter();
    } catch (error) {
      reader.releaseLock();
      throw error;
    }
    const client = new SFTPClient(channel, reader, writer, maximumPacketLength, maximumPendingRequests);
    try {
      await client.#writer.write(formatSftpInit({ version: 3, extensions: [] }));
      const extensions = await withAbort(client.#negotiated, options.signal);
      client.#extensions = extensions;
      return client;
    } catch (error) {
      await client.close(error);
      throw error;
    }
  }

  /** Closes the subsystem channel and rejects outstanding requests. */
  async close(reason: unknown = new Error("SFTP client closed")): Promise<void> {
    await this.#terminate(reason, true);
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  /** Gets v3 attributes for a path. */
  async stat(path: string, options: SFTPOperationOptions = {}): Promise<SFTPAttributes> {
    const response = await this.#request(
      (id) => formatSftpStatRequest({ id, path }),
      options.signal,
    );
    if (response.type !== "attributes")
      throw new Error("SFTP server returned an unexpected response to STAT");
    return publicAttributes(response.attributes);
  }

  /**
   * Iterates directory entries, closing the server handle when iteration ends.
   * Aborting or stopping iteration early may close the client because SFTP cannot
   * cancel an in-flight request.
   */
  async *readDir(path: string, options: SFTPOperationOptions = {}): AsyncIterable<SFTPDirectoryEntry> {
    const handle = await this.#open(path, SSH_FXF_READ, options.signal, true);
    let failed = false;
    let failure: unknown;
    let completed = false;
    try {
      while (true) {
        try {
          const response = await this.#request(
            (id) => formatSftpReadDirRequest({ id, handle }),
            options.signal,
          );
          if (response.type !== "name")
            throw new Error("SFTP server returned an unexpected response to READDIR");
          for (const entry of response.entries)
            yield publicDirectoryEntry(entry);
        } catch (error) {
          if (isEof(error)) {
            completed = true;
            return;
          }
          throw error;
        }
      }
    } catch (error) {
      failed = true;
      failure = error;
      throw error;
    } finally {
      if (failed) {
        await this.#cleanupHandle(handle, failure, options.signal);
      } else if (!completed) {
        await this.#terminate(new Error("SFTP directory iteration cancelled"));
      } else {
        await this.#closeHandle(handle);
      }
    }
  }

  /**
   * Opens a file as a Web readable stream. Cancelling the stream closes this client
   * when necessary to retire an in-flight READ; a request already sent may still
   * have a remote side effect because SFTP has no request cancellation message.
   */
  download(path: string, options: SFTPOperationOptions = {}): ReadableStream<Uint8Array> {
    let handle: Uint8Array | undefined;
    let offset = 0n;
    let closed = false;
    let reading = false;
    const close = async (reason?: unknown, terminate = false) => {
      if (closed)
        return;
      closed = true;
      if (terminate || reading || options.signal?.aborted) {
        await this.close(reason ?? abortReason(options.signal!));
      } else if (handle) {
        await this.#closeHandle(handle);
      }
    };

    return new ReadableStream<Uint8Array>({
      start: async () => {
        handle = await this.#open(path, SSH_FXF_READ, options.signal);
      },
      pull: async (controller) => {
        if (!handle || closed)
          return;
        const activeHandle = handle;
        reading = true;
        try {
          let response: Response;
          try {
            response = await this.#request(
              (id) => formatSftpReadRequest({ id, handle: activeHandle, offset, length: MAXIMUM_CHUNK_LENGTH }),
              options.signal,
              true,
            );
          } finally {
            reading = false;
          }
          if (response.type === "data") {
            offset += BigInt(response.data.length);
            if (response.data.length > 0)
              controller.enqueue(response.data);
            return;
          }
          throw new Error("SFTP server returned an unexpected response to READ");
        } catch (error) {
          if (isEof(error)) {
            await close();
            controller.close();
            return;
          }
          await close(error);
          controller.error(error);
        }
      },
      cancel: (reason) => close(reason ?? new Error("SFTP download cancelled"), true),
    });
  }

  /**
   * Uploads bytes or a Web readable stream, writing sequentially to one open file
   * handle. Aborting may close the client to bound completion of in-flight work;
   * requests already sent may still affect the remote file.
   */
  async upload(
    path: string,
    source: Uint8Array | ReadableStream<Uint8Array>,
    options: SFTPUploadOptions = {},
  ): Promise<void> {
    const create = options.create ?? true;
    const truncate = options.truncate ?? true;
    let flags = SSH_FXF_WRITE;
    if (create) flags |= SSH_FXF_CREAT;
    if (truncate) flags |= SSH_FXF_TRUNC;
    const handle = await this.#open(path, flags, options.signal);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let offset = 0n;
    let failed = false;
    let failure: unknown;
    let cleanupFailed = false;
    let cleanupFailure: unknown;
    try {
      if (source instanceof Uint8Array) {
        await this.#writeBytes(handle, source, offset, options.signal);
      } else {
        reader = source.getReader();
        while (true) {
          throwIfAborted(options.signal);
          const { done, value } = await withAbort(reader.read(), options.signal);
          if (done)
            break;
          await this.#writeBytes(handle, value, offset, options.signal);
          offset += BigInt(value.length);
        }
      }
    } catch (error) {
      failed = true;
      failure = error;
      throw error;
    } finally {
      if (reader) {
        if (failed) {
          try {
            await reader.cancel(failure);
          } catch (error) {
            cleanupFailed = true;
            cleanupFailure = error;
          }
        }
        try {
          reader.releaseLock();
        } catch (error) {
          if (!cleanupFailed) {
            cleanupFailed = true;
            cleanupFailure = error;
          }
        }
      }
      try {
        if (failed) {
          await this.#cleanupHandle(handle, failure, options.signal);
        } else {
          await this.#closeHandle(handle);
        }
      } catch (error) {
        if (!cleanupFailed) {
          cleanupFailed = true;
          cleanupFailure = error;
        }
      }
    }
    if (cleanupFailed)
      throw cleanupFailure;
  }

  async #writeBytes(handle: Uint8Array, bytes: Uint8Array, offset: bigint, signal?: AbortSignal): Promise<void> {
    for (let start = 0; start < bytes.length; start += MAXIMUM_CHUNK_LENGTH) {
      const data = bytes.subarray(start, Math.min(start + MAXIMUM_CHUNK_LENGTH, bytes.length));
      const response = await this.#request(
        (id) => formatSftpWriteRequest({ id, handle, offset: offset + BigInt(start), data }),
        signal,
      );
      if (response.type !== "status" || response.code !== SSH_FX_OK)
        throw new Error("SFTP server returned an unexpected response to WRITE");
    }
  }

  async #open(path: string, flags: number, signal?: AbortSignal, directory = false): Promise<Uint8Array> {
    const response = await this.#request(
      (id) => directory ? formatSftpOpenDirRequest({ id, path }) : formatSftpOpenRequest({ id, path, pflags: flags }),
      signal,
    );
    if (response.type !== "handle")
      throw new Error(`SFTP server returned an unexpected response to ${directory ? "OPENDIR" : "OPEN"}`);
    return response.handle;
  }

  async #closeHandle(handle: Uint8Array): Promise<void> {
    if (this.#closed)
      return;
    const response = await this.#request((id) => formatSftpCloseRequest({ id, handle }));
    if (response.type !== "status" || response.code !== SSH_FX_OK)
      throw new Error("SFTP server returned an unexpected response to CLOSE");
  }

  async #cleanupHandle(handle: Uint8Array, primary: unknown, signal?: AbortSignal): Promise<void> {
    try {
      if (signal?.aborted) {
        await this.#terminate(primary);
      } else {
        await this.#closeHandle(handle);
      }
    } catch {
      // Cleanup must not replace the operation's primary failure.
    }
  }

  async #request(
    format: (id: number) => Uint8Array,
    signal?: AbortSignal,
    terminateOnAbort = false,
  ): Promise<Response> {
    throwIfAborted(signal);
    if (this.#closed)
      throw this.#terminalReason ?? new Error("SFTP client is closed");
    if (this.#pending.size >= this.#maximumPendingRequests)
      throw new Error(`SFTP pending request limit of ${this.#maximumPendingRequests} reached`);
    const id = this.#allocateId();
    const packet = format(id);
    let pending!: Pending;
    const response = new Promise<Response>((resolve, reject) => {
      pending = { resolve, reject, signal, sent: false, terminateOnAbort };
    });
    this.#pending.set(id, pending);
    if (signal) {
      pending.abort = () => {
        this.#pending.delete(id);
        pending.reject(abortReason(signal));
        if (pending.sent && pending.terminateOnAbort)
          void this.#terminate(abortReason(signal));
      };
      signal.addEventListener("abort", pending.abort, { once: true });
    }
    if (signal?.aborted) {
      pending.abort!();
      return await response;
    }
    try {
      pending.sent = true;
      await this.#writer.write(packet);
    } catch (error) {
      this.#pending.delete(id);
      this.#detach(pending);
      pending.reject(error);
      void this.#terminate(error);
    }
    return await response;
  }

  #allocateId(): number {
    for (let count = 0; count <= 0xffff_ffff; count++) {
      const id = this.#nextId;
      this.#nextId = (this.#nextId + 1) >>> 0;
      if (!this.#pending.has(id))
        return id;
    }
    throw new Error("SFTP request ID space is exhausted");
  }

  async #readLoop(): Promise<void> {
    try {
      while (!this.#closed) {
        const { done, value } = await this.#reader.read();
        if (done)
          throw new Error("SFTP channel closed");
        this.#receive(value);
      }
    } catch (error) {
      await this.#terminate(error);
    }
  }

  #receive(chunk: Uint8Array): void {
    let offset = 0;
    while (offset < chunk.length) {
      if (!this.#frame) {
        const count = Math.min(4 - this.#headerLength, chunk.length - offset);
        this.#header.set(chunk.subarray(offset, offset + count), this.#headerLength);
        this.#headerLength += count;
        offset += count;
        if (this.#headerLength < 4)
          continue;
        const length = new DataView(this.#header.buffer).getUint32(0);
        if (length < 1 || length > this.#maximumPacketLength)
          readSftpPacket(this.#header, this.#maximumPacketLength);
        this.#frame = new Uint8Array(length + 4);
        this.#frame.set(this.#header);
        this.#frameLength = 4;
        this.#headerLength = 0;
      }
      const count = Math.min(this.#frame.length - this.#frameLength, chunk.length - offset);
      this.#frame.set(chunk.subarray(offset, offset + count), this.#frameLength);
      this.#frameLength += count;
      offset += count;
      if (this.#frameLength === this.#frame.length) {
        const frame = this.#frame;
        this.#frame = undefined;
        this.#frameLength = 0;
        this.#dispatch(frame);
      }
    }
  }

  #dispatch(packet: Uint8Array): void {
    const framed = readSftpPacket(packet, this.#maximumPacketLength);
    if (!framed)
      throw new Error("internal SFTP packet framing error");
    if (this.#awaitingVersion) {
      if (framed.type !== SSH_FXP_VERSION)
        throw new Error("expected SFTP version response");
      const version = parseSftpVersion(packet, this.#maximumPacketLength);
      if (!version)
        throw new Error("incomplete SFTP version response");
      if (version.version !== 3)
        throw new Error(`SFTP server version ${version.version} is not supported`);
      const extensions = Object.freeze(version.extensions.map((extension) =>
        Object.freeze({
          name: extension.name,
          data: extension.data.slice(),
        })
      ));
      this.#awaitingVersion = false;
      this.#versionResolve(extensions);
      return;
    }

    let id: number;
    let response: Response;
    switch (framed.type) {
      case SSH_FXP_HANDLE: {
        const value = parseSftpHandle(packet, this.#maximumPacketLength);
        if (!value) throw new Error("incomplete SFTP handle response");
        id = value.id;
        response = { type: "handle", handle: value.handle };
        break;
      }
      case SSH_FXP_DATA: {
        const value = parseSftpData(packet, this.#maximumPacketLength);
        if (!value) throw new Error("incomplete SFTP data response");
        id = value.id;
        response = { type: "data", data: value.data };
        break;
      }
      case SSH_FXP_NAME: {
        const value = parseSftpName(packet, this.#maximumPacketLength);
        if (!value) throw new Error("incomplete SFTP name response");
        id = value.id;
        response = { type: "name", entries: value.entries };
        break;
      }
      case SSH_FXP_ATTRS: {
        const value = parseSftpAttributes(packet, this.#maximumPacketLength);
        if (!value) throw new Error("incomplete SFTP attributes response");
        id = value.id;
        response = { type: "attributes", attributes: value.attributes };
        break;
      }
      case SSH_FXP_STATUS: {
        const value = parseSftpStatus(packet, this.#maximumPacketLength);
        if (!value) throw new Error("incomplete SFTP status response");
        id = value.id;
        response = { type: "status", code: value.code, message: value.message, languageTag: value.languageTag };
        break;
      }
      default:
        throw new Error(`unexpected SFTP response type ${framed.type}`);
    }
    const pending = this.#pending.get(id);
    if (!pending)
      return;
    this.#pending.delete(id);
    this.#detach(pending);
    if (response.type === "status" && response.code !== SSH_FX_OK)
      pending.reject(new SFTPStatusError(response.code, response.message, response.languageTag));
    else
      pending.resolve(response);
  }

  #detach(pending: Pending): void {
    if (pending.signal && pending.abort)
      pending.signal.removeEventListener("abort", pending.abort);
  }

  #terminate(reason: unknown, normalClose = false): Promise<void> {
    if (!this.#closed) {
      this.#closed = true;
      this.#terminalReason = reason;
      this.#versionReject(reason);
      for (const pending of this.#pending.values()) {
        this.#detach(pending);
        pending.reject(reason);
      }
      this.#pending.clear();
    }
    if (!this.#shutdown) {
      const terminalReason = this.#terminalReason;
      this.#shutdown = (async () => {
        const cleanup: Promise<unknown>[] = [];
        if (this.#channel.close) {
          // A normal public close must let managed channels retire only their own SSH channel.
          cleanup.push(
            Promise.resolve().then(() => normalClose ? this.#channel.close!() : this.#channel.close!(terminalReason)),
          );
        }
        cleanup.push(Promise.resolve().then(() => this.#writer.abort(terminalReason)));
        cleanup.push(Promise.resolve().then(() => this.#reader.cancel(terminalReason)));
        await Promise.allSettled(cleanup);
        if (!this.#readerReleased) {
          this.#readerReleased = true;
          try {
            this.#reader.releaseLock();
          } catch {
            // Another stream cleanup path may already have released it.
          }
        }
        if (!this.#writerReleased) {
          this.#writerReleased = true;
          try {
            this.#writer.releaseLock();
          } catch {
            // Another stream cleanup path may already have released it.
          }
        }
      })();
    }
    return this.#shutdown;
  }
}

function publicAttributes(attributes: RawAttributes): SFTPAttributes {
  return Object.freeze({
    ...attributes,
    extended: attributes.extended?.map((extension) =>
      Object.freeze({
        type: extension.type,
        data: extension.data.slice(),
      })
    ),
  });
}

function publicDirectoryEntry(entry: RawNameEntry): SFTPDirectoryEntry {
  return Object.freeze({
    filename: entry.filename,
    longname: entry.longname,
    attributes: publicAttributes(entry.attributes),
  });
}

function validateMaximumPacketLength(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff)
    throw new RangeError("maximumPacketLength must be an integer between 1 and 2^32 - 1");
}

function validateMaximumPendingRequests(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff)
    throw new RangeError("maximumPendingRequests must be an integer between 1 and 2^32 - 1");
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted)
    throw abortReason(signal);
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new Error("SFTP operation was aborted");
}

function isEof(error: unknown): error is SFTPStatusError {
  return error instanceof SFTPStatusError && error.code === SSH_FX_EOF;
}

async function withAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  throwIfAborted(signal);
  if (!signal)
    return await promise;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(abortReason(signal));
    signal.addEventListener("abort", abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
