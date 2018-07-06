// tslint:disable:no-console
import { randomBytes } from 'crypto';
import { createReadStream, createWriteStream, unlinkSync } from 'fs';
import meow from 'meow';
import { tmpdir } from 'os';
import { join as pathJoin } from 'path';
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
  $ npx aescrypt -d -o baz.txt bar.txt.aes
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
    }

    if (!this.options.input || this.options.input.length === 0) {
      this.options.input = ['-'];
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
  public async execute(): Promise<any> {
    const { decrypt, input, output } = this.options;
    let { password } = this.options;
    let tmpFile = '';
    if (!password) {
      // If we need to get the password on the stdin, but we have a data stream`
      // coming that way, we need to consume the data, so make room for the password.
      if (input[0] === '-') {
        tmpFile = await this._stashStdIn();
        input[0] = tmpFile;

        // I can't figure out how to get both the data and password on the stdin.
        unlinkSync(tmpFile);
        this.error(
          'Error: You must provide the password if you are stream the data on STDIN.'
        );
      }
      password = await this._getPasswordOnStdIn();
    }
    // This would be a great use of async.
    return Promise.all(
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
    )
      .then(() => {
        if (tmpFile) {
          unlinkSync(tmpFile);
        }
      })
      .catch(e => {
        if (tmpFile) {
          unlinkSync(tmpFile);
        }
        this.error(e.name + ': ' + e.message);
      });
  }
  public error(message: string, code: number = 1): void {
    console.error(message);
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
  private _promptSecret(prompt: string): Promise<string> {
    const BACKSPACE = String.fromCharCode(127);
    return new Promise(resolve => {
      const stdin = process.stdin;
      const stdout = process.stdout;

      stdin.resume();
      stdin.setEncoding('utf8');
      if (stdin.setRawMode) {
        stdin.setRawMode(true);
      }

      stdout.write(prompt);

      let password = '';
      const onData = (b: Buffer) => {
        const ch = b.toString('utf8');

        switch (ch) {
          case '\n': /* falls through */
          case '\r': /* falls through */
          case '\u0004':
            // They've finished typing their password
            stdin.removeListener('data', onData);
            process.stdout.write('\n');
            if (stdin.setRawMode) {
              stdin.setRawMode(false);
            }
            stdin.pause();
            resolve(password);
            break;
          case '\u0003':
            // Ctrl-C
            process.stdout.write('\n');
            process.exit();
            break;
          case BACKSPACE:
            password = password.slice(0, password.length - 1);
            const tmp: any = stdout;
            tmp.clearLine();
            tmp.cursorTo(0);
            stdout.write(prompt);
            stdout.write(
              password
                .split('')
                .map(() => '*')
                .join('')
            );
            break;
          default:
            // More passsword characters
            process.stdout.write('*');
            password += ch;
            break;
        }
      };

      stdin.on('data', onData);
    });
  }
  private _getPasswordOnStdIn(): Promise<string> {
    let pass = '';
    return this._promptSecret('Enter password: ')
      .then(password => {
        pass = password;
        return this._promptSecret('Re-Enter password: ');
      })
      .then(verify => {
        if (pass !== verify) {
          this.error("Error: Passwords don't match.");
        }
        return pass;
      });
  }
  private _stashStdIn(): Promise<string> {
    return new Promise((resolve, reject) => {
      const from = process.stdin;
      const outfile = pathJoin(
        tmpdir(),
        'tmp' + randomBytes(16).toString('base64')
      );
      const to = createWriteStream(outfile);
      from
        .pipe(to)
        .on('error', reject)
        .on('finish', () => {
          resolve(outfile);
        });
    });
  }
}

const app = new CLI();
app.execute();
