import { describe, it, expect } from 'vitest';
import { Readable, Writable } from 'stream';
import { Decrypt } from './lib/decrypt';
import { Encrypt } from './lib/encrypt';
import { toStream, withStream } from './lib/util';

const getRandomReadable = (length: number) => {
  let left = length;
  return new Readable({
    read(size: number | undefined): void {
      const len = Math.min(left, size ? size : left);
      const buff = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; ++i) {
        buff.writeUInt8(Math.floor(Math.random() * 256), i);
      }
      this.push(buff);
      left -= len;
      // If we are done, Send the close signal.
      if (left <= 0) {
        this.push(null);
      }
    },
  });
};
export type WithStreamCallback = (decryptedLength: number) => void;
const getLengthWritable = (cb: WithStreamCallback) => {
  let decryptedLength: number = 0;
  return new Writable({
    write(chunk: Buffer, _, callback): void {
      decryptedLength += chunk.length;
      callback();
    },
    final(callback): void {
      cb(decryptedLength);
      callback();
    },
  });
};

const KNOWN_TEST_FILE =
  'QUVTAgAAGENSRUFURURfQlkAYWVzY3J5cHQgMy4wNQCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIz7OO6zNM6K3hu7TWh/aXzkxPhn/cyCvp+dzNsZilUAxaUWnX4R8CfM0rYXPBOXQ+S0rUf4kAp0us9MEPlNOWSZDgY3tP2/Y2oAm9rOcaWUyWySwDM01UxaDWcLOrp+w0YcH4isUGd2KVIHmmHl68FKwcyY2kikIL+dolT07q6Lo+wL8hVDAmxWNm2Oj23eAk=';
const KNOWN_TEST_PASSWORD = 'test';
const KNOWN_CONTENTS = 'test\n';

describe('Encrypt', () => {
  it('should create an AES encrypted file', async () => {
    const contents = await Encrypt.buffer(KNOWN_TEST_PASSWORD, Buffer.from(KNOWN_CONTENTS));
    expect(contents.slice(0, 3).toString()).toBe('AES');
  });
});

describe('Decrypt', () => {
  it('should be able to decrypt an AES encrypted file', async () => {
    const contents = await Decrypt.buffer(
      KNOWN_TEST_PASSWORD,
      Buffer.from(KNOWN_TEST_FILE, 'base64')
    );
    expect(contents.toString()).toBe(KNOWN_CONTENTS);
  });
});

describe('Encrypt-Decrypt', () => {
  it('should get the same contents after decrypting then before encrypting', async () => {
    await new Promise<void>((resolve, reject) => {
      const s = toStream(KNOWN_CONTENTS);
      const w = withStream(contents => {
        expect(contents.toString()).toBe(KNOWN_CONTENTS);
        resolve();
      });
      s.pipe(new Encrypt(KNOWN_TEST_PASSWORD))
        .pipe(new Decrypt(KNOWN_TEST_PASSWORD))
        .pipe(w)
        .on('error', reject);
    });
  });

  it('should be able to encrypt/decrypt large random files', async () => {
    const expectedLength = 1000000;
    await new Promise<void>((resolve, reject) => {
      const s = getRandomReadable(expectedLength);
      const w = getLengthWritable(actualLength => {
        expect(actualLength).toBe(expectedLength);
        resolve();
      });
      s.pipe(new Encrypt(KNOWN_TEST_PASSWORD))
        .pipe(new Decrypt(KNOWN_TEST_PASSWORD))
        .pipe(w)
        .on('error', reject);
    });
  });
});
