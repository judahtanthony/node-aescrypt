import { createHash, createHmac, Hmac } from 'crypto';
import { readFileSync } from 'fs';
import { resolve as pathResolve } from 'path';
import { Readable, Writable, Transform } from 'stream';

const readPackageJson = (path: string) =>
  JSON.parse(readFileSync(path, 'utf8'));

const pkg = readPackageJson(pathResolve(__dirname, '../../../package.json'));

export const NAME = pkg.name;
export const VERSION = pkg.version;
export const AESCRYPT_FILE_FORMAT_VERSION = 2;

/**
 * Callback signature for Transform stream's _transform and _flush methods.
 * @param error - An optional error if one occurred.
 * @param data - Optional data chunk if emitting data from _transform.
 */
export type TransformCallback = (error?: Error | null, data?: Buffer) => void;

/**
 * Generates an encryption key from a password and an Initialization Vector (IV).
 * This function implements the key derivation algorithm used by AES Crypt,
 * which involves repeated SHA256 hashing.
 * @param iv - The Initialization Vector (must be 16 bytes for AES-256).
 * @param password - The password to derive the key from.
 * @returns A 32-byte encryption key.
 */
export function getKey(iv: Buffer, password: string): Buffer {
  // This is a clever trick to do all the hashing rounds into a single buffer.
  // Note, sha255 is always 32 bytes and unicode is 2 bytes for each character.
  const buffer = Buffer.alloc(32 + password.length * 2);
  iv.copy(buffer, 0); // Write the IV.
  // Looks like the algorithm expects unicode.
  for (let i = 0; i < password.length; ++i) {
    buffer.writeUInt8(password.charCodeAt(i) & 0xff, 32 + i * 2);
    buffer.writeUInt8(password.charCodeAt(i) >>> 8, 32 + i * 2 + 1);
  }
  let round = 8192;
  while (round--) {
    // Hash and feed back into same buffer.
    createHash('sha256').update(buffer).digest().copy(buffer, 0);
  }
  return buffer.slice(0, 32);
}

export function getHMAC(key: Buffer): Hmac {
  return createHmac('sha256', key);
}

export function toStream(contents: Buffer | string): Readable {
  let remaining = contents;
  return new Readable({
    read(size: number | undefined): void {
      if (size && size >= remaining.length) {
        this.push(remaining);
        this.push(null);
      } else {
        this.push(remaining.slice(0, size));
        remaining = remaining.slice(size);
      }
    },
  });
}

/**
 * Processes a buffer by piping it through a given transform stream.
 * This is a utility function to handle the common pattern of encrypting/decrypting
 * an entire buffer at once.
 * @param buffer - The input buffer to process.
 * @param transformInstance - An instance of a Transform stream (e.g., Encrypt or Decrypt).
 * @returns A Promise that resolves with the processed buffer or rejects on error.
 */
export function processBufferWithTransform(
  buffer: Buffer,
  transformInstance: Transform
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    toStream(buffer)
      .pipe(transformInstance)
      .pipe(
        withStream((contents) => {
          resolve(contents);
        })
      )
      .on('error', reject);
  });
}

/**
 * Callback signature for the `withStream` utility.
 * Called with the fully accumulated buffer when the writable stream finishes.
 * @param contents - The accumulated buffer from the stream.
 */
export type WithStreamCallback = (contents: Buffer) => void;

/**
 * Creates a Writable stream that accumulates all chunks written to it
 * and then calls a callback with the concatenated buffer upon finishing.
 * @param cb - The callback to execute with the final accumulated buffer.
 * @returns A Writable stream.
 */
export function withStream(cb: WithStreamCallback): Writable {
  const buffers: Buffer[] = [];
  return new Writable({
    write(chunk: Buffer, _, callback): void {
      buffers.push(chunk);
      callback();
    },
    final(callback): void {
      cb(Buffer.concat(buffers));
      callback();
    },
  });
}
