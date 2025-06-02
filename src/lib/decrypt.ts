import { createDecipheriv, Decipher, Hmac } from 'crypto';
import { Transform, TransformOptions } from 'stream';
import {
  AESCRYPT_FILE_FORMAT_VERSION,
  getHMAC,
  getKey,
  TransformCallback,
  processBufferWithTransform,
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
  /** @internal File header reading mode. */
  static get MODE_FILE_HEADER(): number {
    return 0;
  }
  /** @internal Extensions reading mode. */
  static get MODE_EXTESIONS(): number {
    return 1;
  }
  /** @internal Credentials (IV and key) reading mode. */
  static get MODE_CREDENTIALS(): number {
    return 2;
  }
  /** @internal Main content decryption mode. */
  static get MODE_DECRYPT(): number {
    return 3;
  }

  /**
   * A static helper method to decrypt an entire buffer at once.
   * @param password - The password to use for decryption.
   * @param buffer - The encrypted buffer (in AES Crypt file format).
   * @returns A Promise that resolves with the decrypted (plaintext) buffer.
   */
  public static buffer(password: string, buffer: Buffer): Promise<Buffer> {
    const decryptInstance = new Decrypt(password);
    return processBufferWithTransform(buffer, decryptInstance);
  }

  private password?: string; // Stores the password temporarily
  private decipher: Decipher | null; // AES decipher instance
  private hmac: Hmac | null; // HMAC instance for integrity checking
  private mode: number; // Current mode in the state machine for parsing file format
  private buffer: Buffer; // Internal buffer to accumulate incoming chunks

  /**
   * Creates an instance of the Decrypt stream.
   * @param password - The password to use for decryption.
   * @param options - Optional stream transform options.
   */
  constructor(password: string, options?: TransformOptions) {
    super(options);
    this.password = password;
    this.decipher = null;
    this.hmac = null;
    this.mode = Decrypt.MODE_FILE_HEADER; // Start in header reading mode
    this.buffer = Buffer.alloc(0);
  }

  /**
   * Internal _transform method for the Transform stream.
   * Processes incoming chunks of encrypted data, parsing the AES Crypt
   * file format, and eventually decrypting and pushing plaintext data.
   * @param chunk - The chunk of encrypted data.
   * @param _encoding - The encoding of the chunk (ignored).
   * @param callback - Callback to signal completion of processing this chunk.
   */
  public _transform(
    chunk: Buffer,
    _encoding: string, // Parameter name changed for clarity
    callback: TransformCallback
  ): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    let error: Error | null = null; // Ensure error is typed
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

  /**
   * Internal _flush method for the Transform stream.
   * Called when all encrypted data has been written. It performs final
   * HMAC verification and pushes any remaining decrypted data.
   * @param callback - Callback to signal completion of the flushing process.
   */
  public _flush(callback: TransformCallback): void {
    let error: Error | null = null; // Ensure error is typed

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
      if (this.password === undefined) {
        return new Error('Password is not defined');
      }
      const credKey = getKey(credIV, this.password);
      const credDecipher = this._getDecipher(credKey, credIV);
      credDecipher.setAutoPadding(false);
      const credBlock = this.buffer.slice(16, 64);
      const credHMACActual = this.buffer.slice(64, 96);
      const credHMACExpected = getHMAC(credKey).update(credBlock).digest();
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
