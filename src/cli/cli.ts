// tslint:disable:no-console
import { createReadStream, createWriteStream } from 'fs';
import meow from 'meow';
import { Readable, Writable } from 'stream';
import { Decrypt, Encrypt } from '../index';

const CLI_HELP_TEXT = `
Usage
  $ npx aescrypt {-e|-d} [-p <password>] { [-o <output filename>] <file> | <file> [<file> ...] }

Arguements
  Provide one or more files to be encrypted or decrypted.  If you are decrypting a file, it should have a .aes extension.

Options
  --encrypt, -e       Encrypt the input file
  --decrypt, -d       Decrypt the input file
  --password, -p      Use the provided password
  --output, -o        Specify the output filename
  --version           Get version information
  --help              Outputs this help text

Examples
  $ npx aescrypt -e -p foo bar.txt
  $ npx aescrypt -d bar.txt.aes -o baz.txt 
  $ cat baz.txt | npx aescrypt -e -p test > encrypted.aes
`;

interface Options {
  encrypt?: boolean;
  decrypt?: boolean;
  password?: string;
  output?: string;
  input?: string[];
}

class CLI {
  private options: Options | any;
  constructor() {
    try {
      const cli = meow(CLI_HELP_TEXT, {
        flags: {
          decrypt: { alias: 'd', type: 'boolean' },
          encrypt: { alias: 'e', type: 'boolean' },
          output: { alias: 'o', type: 'string' },
          password: { alias: 'p', type: 'string' },
        },
      });
      this.options = {
        input: cli.input,
        ...cli.flags,
      };
    } catch (e) {
      this.error('Error: Invalid format');
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

    if (!this.options.input || this.options.input.length === 0) {
      this.error('Error: No file argument specified');
    }
    if (this.options.input.length > 1) {
      if (this.options.output) {
        this.error(
          'Error: A single output file may not be specified with multiple input files.'
        );
      }
      if (this.options.input.indexOf('-') !== -1) {
        this.error(
          'Error: STDIN may not be specified with multiple input files.'
        );
      }
    }
    if (
      this.options.decrypt &&
      this.options.input[0] !== '-' &&
      this.options.input.find((infile: string) => infile.substr(-4) !== '.aes')
    ) {
      this.error("Error: your input file doesn't end in .aes");
    }
  }
  public execute(): void {
    const { decrypt, input, output, password } = this.options;
    // This would be a great use of async.
    Promise.all(
      input.map(
        (infile: string) =>
          new Promise((resolve, reject) => {
            const from = this._getFromStream(infile);
            const to = this._getToStream(infile, output, decrypt);
            const through = decrypt
              ? new Decrypt(password)
              : new Encrypt(password);
            from
              .pipe(through)
              .pipe(to)
              .on('error', reject)
              .on('finish', resolve);
          })
      )
    ).catch(e => this.error(e.name + ': ' + e.message));
  }
  public error(message: string, code: number = 1): void {
    console.error(message);
    console.info('\n' + CLI_HELP_TEXT);
    process.exit(code);
  }
  private _getFromStream(input: string): Readable {
    return input === '-' ? process.stdin : createReadStream(input);
  }
  private _getToStream(
    input: string,
    output?: string,
    decrypt?: boolean
  ): Writable {
    if (output === '-' || (input === '-' && !output)) {
      return process.stdout;
    }
    let outfile = output;
    if (!outfile) {
      outfile = decrypt ? input.substr(0, input.length - 4) : input + '.aes';
    }
    return createWriteStream(outfile);
  }
}

const app = new CLI();
app.execute();
