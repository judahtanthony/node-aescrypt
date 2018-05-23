import { Readable, Writable } from "stream";
import {
  Hmac,
  createHmac,
  createHash } from "crypto";

const pkg = require('../package.json');

export const NAME = pkg.name;
export const VERSION = pkg.version;
export const AESCRYPT_FILE_FORMAT_VERSION = 2;

export interface TransformCallback {
  (error?:Error, data?:Buffer): void
}

export function getKey(iv:Buffer, password:string):Buffer {
  // This is a clever trick to do all the hashing rounds into a single buffer.
  // Note, sha255 is always 32 bytes and unicode is 2 bytes for each character.
  const buffer = Buffer.alloc(32 + password.length * 2);
  iv.copy(buffer, 0); // Write the IV.
  // Looks like the algorithm expects unicode.
  for (let i = 0; i < password.length; ++i) {
    buffer.writeUInt8(password.charCodeAt(i) & 0xFF, 32 + (i * 2));
    buffer.writeUInt8(password.charCodeAt(i) >>> 8, 32 + (i * 2) + 1);
  }
  let i = 8192;
  while (i--) {
    // Hash and feed back into same buffer.
    createHash('sha256').update(buffer).digest().copy(buffer, 0);
  }
  return buffer.slice(0, 32);
};

export function getHMAC(key:Buffer):Hmac {
  return createHmac('sha256', key);
}

export function toStream(contents:Buffer|string):Readable {
  return new Readable({
    read: function(size) {
      if (size >= contents.length) {
        this.push(contents);
        this.push(null);
      }
      else {
        this.push(contents.slice(0, size));
        contents = contents.slice(size);
      }
    }
  });
}

export interface WithStreamCallback {
  (contents:Buffer): void
}
export function withStream(cb:WithStreamCallback):Writable {
  let buffers = [];
  return new Writable({
    write: function(chunk, encoding, callback) {
      buffers.push(chunk);
      callback();
    },
    final: function(callback) {
      cb(Buffer.concat(buffers));
      callback();
    }
  });
}
