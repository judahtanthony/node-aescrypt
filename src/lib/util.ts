import { createHash, createHmac, Hmac } from 'crypto';
import { readFileSync } from 'fs';
import { resolve as pathResolve } from 'path';
import { Readable, Writable } from 'stream';

const readPackageJson = (path: string) =>
  JSON.parse(readFileSync(path, 'utf8'));

const pkg = readPackageJson(pathResolve(__dirname, '../../../package.json'));

export const NAME = pkg.name;
export const VERSION = pkg.version;
export const AESCRYPT_FILE_FORMAT_VERSION = 2;

export type TransformCallback = (error?: Error, data?: Buffer) => void;

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
    createHash('sha256')
      .update(buffer)
      .digest()
      .copy(buffer, 0);
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

export type WithStreamCallback = (contents: Buffer) => void;
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
