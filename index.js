const fs = require('fs');
const stream = require('stream');
const crypto = require('crypto');

const pkg = require('./package.json');

function getKey(iv, password) {
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
    crypto.createHash('sha256').update(buffer).digest().copy(buffer, 0);
  }
  return buffer.slice(0, 32);
};
function getHMAC(key) {
  return crypto.createHmac('sha256', key);
}

class Encrypt extends stream.Transform {
  constructor(password, options) {
    super(options);
    this.password = password;
    this.cipher = null;
    this.hmac = null;
    this.contentLength = 0;
    // Delay initialization.
  }
  _init() {
    if (!this.cipher) {
      const credentials = this._getCredentials(this.password);

      delete this.password; // Don't need this anymore.

      this.push(credentials.block);

      this.cipher = this._getCipher(credentials.key, credentials.iv);
      this.hmac = getHMAC(credentials.key);

      return true;
    }
    return false;
  }
  _transform(chunk, encoding, callback) {
    this._init();

    this.contentLength += chunk.length;
    const encChunk = this.cipher.update(chunk);
    this.push(encChunk);
    this.hmac.update(encChunk);

    callback();
  }
  _flush(callback) {
    this._init();

    const lenMod16 = this.contentLength % 16;
    const padding = 16 - lenMod16;

    const encChunk = this.cipher.update(Buffer.alloc(padding, padding));
    this.push(encChunk);
    this.hmac.update(encChunk);

    this.push(this.cipher.final()); // This one should be unnecessary, as we are disabling the padding, but just in case.
    this.push(Buffer.from([lenMod16]));
    this.push(this.hmac.digest());

    callback();
  }
  _getCredentials(password) {
    const extensions = {
      "CREATED_BY": pkg.name + ' ' + pkg.version,
    };
    const capacity = 3 // file header
      + 1 // version
      + 1 // delimiter
      + (Object.keys(extensions).reduce((acc, k) => (2 + k.length + 1 + extensions[k].length), 0)) // Extensions
      + (2 + 128) // extension container
      + 2
      + 16 // credIV
      + 48 // credBlock: 16 encIV + 32 encKey
      + 32 // credHMAC
      ;
    let len = 0;
    const buff = Buffer.alloc(capacity);
    len += buff.write('AES', len);
    len = buff.writeUInt8(2, len);
    len += 1; // Delimiter
    Object.keys(extensions).forEach(k => {
      len = buff.writeUInt16BE(k.length + 1 + extensions[k].length, len);
      len += buff.write(k, len);
      len += 1; // Delimiter
      len += buff.write(extensions[k], len);
    });
    len = buff.writeUInt16BE(128, len);
    len += 128;
    len += 2;

    // Credentials Block.
    const credIV = crypto.randomBytes(16);
    const credKey = getKey(credIV, password);
    const credCipher = this._getCipher(credKey, credIV);
    const encIV = crypto.randomBytes(16);
    const encKey = crypto.randomBytes(32);
    const credBlock = Buffer.concat([
      credCipher.update(encIV),
      credCipher.update(encKey),
      credCipher.final(), // This one should be unnecessary, as we are disabling the padding, but just in case.
    ]);
    const credHMAC = getHMAC(credKey)
                     .update(credBlock)
                     .digest();
    len += credIV.copy(buff, len);
    len += credBlock.copy(buff, len);
    len += credHMAC.copy(buff, len);

    return {
      iv: encIV,
      key: encKey,
      block: buff,
    };
  }
  _getCipher(key, iv) {
    const encCipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    encCipher.setAutoPadding(false);
    return encCipher;
  }
}

class Decrypt extends stream.Transform {
  static get MODE_FILE_HEADER() { return 0; };
  static get MODE_EXTESIONS() { return 1; };
  static get MODE_CREDENTIALS() { return 2; };
  static get MODE_DECRYPT() { return 3; };
  constructor(password, options) {
    super(options);
    this.password = password;
    this.decipher = null;
    this.hmac = null;
    this.mode = 0;
    this.buffer = Buffer.alloc(0);
    // Delay initialization.
  }
  _transform(chunk, encoding, callback) {
    this.buffer = Buffer.concat([ this.buffer, chunk ]);
    let error = null;
    switch (this.mode) {
      case Decrypt.MODE_FILE_HEADER:
        if (this.buffer.length >= 5) {
          const type = this.buffer.slice(0, 3).toString();
          const version = this.buffer.readUInt8(3);
          if (type !== 'AES') {
            error = new Error('Error: Bad file header (not aescrypt file or is corrupted?');
            break;
          }
          if (version != 2) {
            error = new Error('Error: Unsupported AES file version');
            break;
          }
          this.buffer = this.buffer.slice(5);
          this.mode = Decrypt.MODE_EXTESIONS;
        }
      case Decrypt.MODE_EXTESIONS:
        let i = 0;
        // Search through the buffer to the length.
        while ((i + 1) < this.buffer.length) {
          const extLen = this.buffer.readUInt16BE(i);
          i += 2
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
      case Decrypt.MODE_CREDENTIALS:
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
          if (credHMACExpected.compare(credHMACActual) !== 0) {
            error = new Error('Error: Message has been altered or password is incorrect');
            break;
          }

          const decryptedCredBlock = Buffer.concat([
            credDecipher.update(credBlock),
            credDecipher.final(), // This one should be unnecessary, as we are disabling the padding, but just in case.
          ]);
          const encIV = decryptedCredBlock.slice(0, 16);
          const encKey = decryptedCredBlock.slice(16, 48);

          this.decipher = this._getDecipher(encKey, encIV);
          this.hmac = crypto.createHmac('sha256', encKey);

          this.buffer = this.buffer.slice(96);
          this.mode = Decrypt.MODE_DECRYPT;
        }
      case Decrypt.MODE_DECRYPT:
        // We need to reserve 33 bytes of the end for the file-size-modulo-16 and HMAC.
        if (this.buffer.length > 33) {

        }
    }
    callback(error);
  }
  _flush(callback) {
    callback();
  }
  _getDecipher(key, iv) {
    const encDecipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    encDecipher.setAutoPadding(false);
    return encDecipher;
  }
}

module.exports = {
  Encrypt,
  Decrypt,
};

const OPTION_DEFINITIONS = [
  { name: 'encrypt', alias: 'e', type: Boolean },
  { name: 'decrypt', alias: 'd', type: Boolean },
  { name: 'password', alias: 'p', type: String },
  { name: 'output', alias: 'o', type: String },
  { name: 'input', alias: 'i', type: String, multiple: true, defaultOption: true, defaultValue: '-' },
];

const CLI_HELP = 'usage: aescrypt {-e|-d} [-p <password>] { [-o <output filename>] <file> | <file> [<file> ...] }';

class CLI {
  constructor() {
    const commandLineArgs = require('command-line-args');
    this.options;
    try {
      this.options = commandLineArgs(OPTION_DEFINITIONS);
    }
    catch (e) {
      this.error(CLI_HELP);
    }

    if (this.options.encrypt && this.options.decrypt) {
      this.error('Error: only specify one of -d or -e');
    }
    if (!this.options.encrypt && !this.options.decrypt) {
      this.error('Error: -e or -d not specified');
    }

    if (!this.options.password) {
      this.options.password = process.env.AESCRYPT_PASSWORD;
      // We should really fall back to somekind of command prompt if it is not
      // in the env variable.
      if (!this.options.password) {
        this.error('Error: please provide a password');
      }
    }

    if (!this.options.input || this.options.input.length == 0) {
      this.error('Error: No file argument specified');
    }
    if (this.options.input.length > 1) {
      if (this.options.output) {
        this.error('Error: A single output file may not be specified with multiple input files.');
      }
      if (this.options.input.indexOf('-') !== -1) {
        this.error('Error: STDIN may not be specified with multiple input files.');
      }
    }
    if (this.options.decrypt && this.options.input[0] != '-' && this.options.input.find(infile => infile.substr(-4) !== '.aes')) {
      this.error('Error: your input file doesn\'t end in .aes');
    }
  }
  execute () {
    const { encrypt, decrypt, input, output, password } = this.options;
    // This would be a great use of async.
    Promise.all(input.map(infile => new Promise((resolve, reject) => {
      const from = this._getFromStream(infile);
      const to = this._getToStream(infile, output, decrypt);
      const through = decrypt ? new Decrypt(password) : new Encrypt(password);
      from.pipe(through).pipe(to).on('error', reject).on('finish', resolve);
    })))
    .catch(e => this.error(e.name + ': ' + e.message));
  }
  _getFromStream (input) {
    return input == '-' ? process.stdin : fs.createReadStream(input);
  }
  _getToStream (input, output, decrypt) {
    if (output == '-' || (input == '-' && !output)) {
      return process.stdout;
    }
    let outfile = output;
    if (!outfile) {
      outfile = decrypt ? input.substr(0, input.length - 4) : input + '.aes';
    }
    return fs.createWriteStream(outfile);
  }
  error (message, code=1) {
    console.error(message);
    console.info("\n" + CLI_HELP);
    process.exit(code);
  }
}

if (require.main === module) {
  let app = new CLI();
  app.execute();
}
