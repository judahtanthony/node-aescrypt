import { createDecipheriv, Decipher, Hmac } from 'crypto';
import { Transform } from 'stream';
import {
  AESCRYPT_FILE_FORMAT_VERSION,
  getHMAC,
  getKey,
  toStream,
  TransformCallback,
  withStream,
} from './util';

/**
 * Decrypt a Buffer that is in the AES Crypt file format.
 *
 * Create a stream transformer that takes [Readable stream](https://nodejs.org/api/stream.html)
 * that is encrypted in the
 * [AES Crypt file format](https://www.aescrypt.com/aes_file_format.html) and
 * decrypts it passing it on as a Readable stream.
 */
export class Decrypt extends Transform {
  static get MODE_FILE_HEADER(): number {
    return 0;
  }
  static get MODE_EXTESIONS(): number {
    return 1;
  }
  static get MODE_CREDENTIALS(): number {
    return 2;
  }
  static get MODE_DECRYPT(): number {
    return 3;
  }
  // Create a small helper static method if you just want to decrypt a whole
  // Buffer all at once.
  public static buffer(password: string, buffer: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      toStream(buffer)
        .pipe(new Decrypt(password))
        .pipe(
          withStream(contents => {
            resolve(contents);
          })
        )
        .on('error', reject);
    });
  }

  private password: string;
  private decipher: Decipher | null;
  private hmac: Hmac | null;
  private mode: number;
  private buffer: Buffer;

  constructor(password: string, options?: any) {
    super(options);
    this.password = password;
    this.decipher = null;
    this.hmac = null;
    this.mode = 0;
    this.buffer = Buffer.alloc(0);
  }
  public _transform(
    chunk: Buffer,
    _: string,
    callback: TransformCallback
  ): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    let error = null;
    // Move through the various sections of the file format and raise an error
    // If anything is malformed.
    if (this.mode === Decrypt.MODE_FILE_HEADER) {
      error = this._modeFileHeader();
    }
    if (!error && this.mode === Decrypt.MODE_EXTESIONS) {
      error = this._modeExtensions();
    }
    if (!error && this.mode === Decrypt.MODE_CREDENTIALS) {
      error = this._modeCredentials();
    }
    // Finally ready to decrypt the contents.
    if (!error && this.mode === Decrypt.MODE_DECRYPT) {
      // We need to reserve 33 bytes (+ 16 for the padding) of the end for the file-size-modulo-16 and HMAC.
      if (this.buffer.length > 49) {
        const encChunk = this.buffer.slice(0, -49);

        // This is unnecessary, but makes tslint keep quiet.
        if (this.decipher == null) {
          return;
        }
        if (this.hmac == null) {
          return;
        }

        this.hmac.update(encChunk);
        this.push(this.decipher.update(encChunk));
        this.buffer = this.buffer.slice(-49);
      }
    }
    if (error) {
      callback(error);
    } else {
      callback();
    }
  }
  public _flush(callback: TransformCallback): void {
    let error = null;

    // If we never got to the decryption mode, something went terribly wrong.
    // Most likely, there is a problem in the extensions, and we never found
    // the end.
    if (this.mode !== Decrypt.MODE_DECRYPT) {
      error = new Error(
        'Error: Message has been altered or password is incorrect'
      );
    } else {
      // We are at the end of the file.  Let's hash that last remaining cipher text
      // and check the HMAC.
      const encChunk = this.buffer.slice(0, 16);
      const lenMod16 = this.buffer.readUInt8(16);
      const encHMACActual = this.buffer.slice(17);

      // This is unnecessary, but makes tslint keep quiet.
      if (this.decipher == null) {
        return;
      }
      if (this.hmac == null) {
        return;
      }

      this.hmac.update(encChunk);
      const encHMACExpected = this.hmac.digest();
      // Validately the integrity of the cipher text.
      if (encHMACExpected.compare(encHMACActual) !== 0) {
        error = new Error(
          'Error: Message has been altered or password is incorrect'
        );
      }
      // Validate the padding length (or more accurately, the length of the last block minus the padding).
      else if (lenMod16 > 16) {
        error = new Error(
          'Error: Message has been altered or password is incorrect'
        );
      } else {
        // Decrypt the last block and send it on its way.
        const decChunk = Buffer.concat([
          this.decipher.update(encChunk),
          this.decipher.final(),
        ]).slice(0, lenMod16);
        this.push(decChunk);
      }
    }
    if (error) {
      callback(error);
    } else {
      callback();
    }
  }
  private _modeFileHeader(): Error | null {
    if (this.buffer.length >= 5) {
      const type = this.buffer.slice(0, 3).toString();
      const version = this.buffer.readUInt8(3);
      if (type !== 'AES') {
        return new Error(
          'Error: Bad file header (not aescrypt file or is corrupted?'
        );
      }
      // We only understand the version 2 of the AES Crypt file format as described
      // at https://www.aescrypt.com/aes_file_format.html.
      if (version !== AESCRYPT_FILE_FORMAT_VERSION) {
        return new Error('Error: Unsupported AES file version');
      }
      this.buffer = this.buffer.slice(5);
      this.mode = Decrypt.MODE_EXTESIONS;
    }
    return null;
  }
  private _modeExtensions(): Error | null {
    let i = 0;
    // Search through the buffer to the length.
    // If we can't find the end of the extensions in the current buffer, let it
    // buffer a little more.
    while (i + 1 < this.buffer.length) {
      const extLen = this.buffer.readUInt16BE(i);
      i += 2;
      // If this extension has a length, fast-forward past it.
      if (extLen > 0) {
        i += extLen;
      }
      // If this is a zero length extension, we are done.
      else {
        this.buffer = this.buffer.slice(i);
        this.mode = Decrypt.MODE_CREDENTIALS;
        break;
      }
    }
    return null;
  }
  private _modeCredentials(): Error | null {
    if (this.buffer.length >= 96) {
      const credIV = this.buffer.slice(0, 16);
      const credKey = getKey(credIV, this.password);
      const credDecipher = this._getDecipher(credKey, credIV);
      credDecipher.setAutoPadding(false);
      const credBlock = this.buffer.slice(16, 64);
      const credHMACActual = this.buffer.slice(64, 96);
      const credHMACExpected = getHMAC(credKey)
        .update(credBlock)
        .digest();
      // First we check the HMAC signature of the encrypted credentials block.
      // This ensures nothing was tampered with.  It also has the added benefit
      // of checking the password early on in the decryption process.
      if (credHMACExpected.compare(credHMACActual) !== 0) {
        return new Error(
          'Error: Message has been altered or password is incorrect'
        );
      }
      // Decrypt the credentials we need for the rest of the contents.
      const decryptedCredBlock = Buffer.concat([
        credDecipher.update(credBlock),
        credDecipher.final(), // This one should be unnecessary, as we are disabling the padding, but just in case.
      ]);
      const encIV = decryptedCredBlock.slice(0, 16);
      const encKey = decryptedCredBlock.slice(16, 48);
      // Create our main workhorses using the decrypted credentials.
      this.decipher = this._getDecipher(encKey, encIV);
      this.hmac = getHMAC(encKey);

      delete this.password; // Don't need this anymore.

      this.buffer = this.buffer.slice(96);
      this.mode = Decrypt.MODE_DECRYPT;
    }
    return null;
  }
  private _getDecipher(key: Buffer, iv: Buffer): Decipher {
    const encDecipher = createDecipheriv('aes-256-cbc', key, iv);
    encDecipher.setAutoPadding(false);
    return encDecipher;
  }
}
