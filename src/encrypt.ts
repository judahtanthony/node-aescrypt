import { Transform } from "stream";
import {
  Cipher,
  Hmac,
  createCipheriv,
  randomBytes } from "crypto";
import {
  NAME,
  VERSION,
  AESCRYPT_FILE_FORMAT_VERSION,
  TransformCallback,
  getKey,
  getHMAC,
  toStream,
  withStream } from "./lib";

interface EncryptionCredentials {
  credIV:Buffer;
  credKey:Buffer;
  encIV:Buffer;
  encKey:Buffer;
};

/**
 * Encrypt a Buffer using the AES Crypt file format.
 *
 * Create a stream transformer that takes any [Readable stream](https://nodejs.org/api/stream.html)
 * and passes on a Readable stream of the encrypted Buffer in the
 * [AES Crypt file format](https://www.aescrypt.com/aes_file_format.html).
 */
export class Encrypt extends Transform {
  // Create a small helper static method if you just want to encrypt a whole
  // Buffer all at once.
  // Note: There is a bit of duplication with the Decrypt version of this method.
  static buffer(password:string, buffer:Buffer):Promise<Buffer> {
    return new Promise((resolve, reject) => {
      toStream(buffer)
        .pipe(new Encrypt(password))
        .pipe(withStream(contents => {
          resolve(contents);
        })).on('error', reject);
    });
  }

  password:string;
  cipher:Cipher;
  hmac:Hmac;
  contentLength:number;
  constructor(password:string, options?:any) {
    super(options);
    this.password = password;
    this.cipher = null;
    this.hmac = null;
    this.contentLength = 0;
    // Delay initialization.
  }
  _init():boolean {
    if (!this.cipher) {
      this._pushFileHeader();
      this._pushExtensions();
      const credentials = this._getCredentials(this.password);
      this._pushCredentials(credentials);

      this.cipher = this._getCipher(credentials.encKey, credentials.encIV);
      this.hmac = getHMAC(credentials.encKey);

      delete this.password; // Don't need this anymore.

      return true;
    }
    return false;
  }
  _transform(chunk:Buffer, encoding:string, callback:TransformCallback):void {
    // Okay, we have data.  Let's initialize.
    this._init();

    // Track the file contents size.
    this.contentLength += chunk.length;
    // Encrypt this chunk and push it.
    const encChunk = this.cipher.update(chunk);
    this.push(encChunk);
    // And add the encrypted cipher block to the signature.
    this.hmac.update(encChunk);

    callback();
  }
  _flush(callback:TransformCallback):void {
    // Make sure we have initialized (even if it is an empty file).
    this._init();

    // Store the size of the last block and determin the padding.
    const lenMod16 = this.contentLength % 16;
    const padding = 16 - lenMod16;
    // Encrypt and sign the padding.
    const encChunk = this.cipher.update(Buffer.alloc(padding, padding));
    this.push(encChunk);
    this.hmac.update(encChunk);
    // Push down the final encryption, size of the last content block and the signature.
    this.push(this.cipher.final()); // This one should be unnecessary, as we are disabling the padding, but just in case.
    this.push(Buffer.from([lenMod16]));
    this.push(this.hmac.digest());

    callback();
  }
  _pushFileHeader():void {
    const buff = Buffer.alloc(3 + 1 + 1);
    buff.write('AES', 0);
    buff.writeUInt8(AESCRYPT_FILE_FORMAT_VERSION, 3);

    this.push(buff);
  }
  _pushExtensions():void {
    const extensions = {
      "CREATED_BY": NAME + ' ' + VERSION,
    };
    // Calculate the final length of the extensions.
    const capacity = (Object.keys(extensions)
      .reduce((acc, k) => (2 + k.length + 1 + extensions[k].length), 0)
    ) // Extensions
      + (2 + 128) // extension container
      + 2; // end extensions
    // Allocate a single buffer for all the extensions.
    const buff = Buffer.alloc(capacity);
    let len = 0;
    Object.keys(extensions).forEach(k => {
      len = buff.writeUInt16BE(k.length + 1 + extensions[k].length, len);
      len += buff.write(k, len);
      len += 1; // Delimiter
      len += buff.write(extensions[k], len);
    });
    len = buff.writeUInt16BE(128, len);
    // We don't need to actually "create" the extension container, as it is just
    // 0x00s, and that is the default fill from Buffer.alloc().

    this.push(buff);
  }
  _getCredentials(password:string):EncryptionCredentials {
    const credIV = randomBytes(16);
    return {
      credIV,
      credKey: getKey(credIV, password),
      encIV: randomBytes(16),
      encKey: randomBytes(32),
    };
  }
  _pushCredentials(credentials:EncryptionCredentials):void {
    const { credIV, credKey, encIV, encKey } = credentials;
    // Encrypt our credentials.
    const credCipher = this._getCipher(credKey, credIV);
    const credBlock = Buffer.concat([
      credCipher.update(encIV),
      credCipher.update(encKey),
      credCipher.final(), // This one should be unnecessary, as we are disabling the padding, but just in case.
    ]);
    // Sign them.
    const credHMAC = getHMAC(credKey)
                     .update(credBlock)
                     .digest();
    // Than push them downstream.
    this.push(credIV);
    this.push(credBlock);
    this.push(credHMAC);
  }
  _getCipher(key:Buffer, iv:Buffer):Cipher {
    const encCipher = createCipheriv('aes-256-cbc', key, iv);
    encCipher.setAutoPadding(false);
    return encCipher;
  }
}
