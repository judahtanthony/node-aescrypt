// tslint:disable:no-console
import { randomBytes } from 'crypto';
import { createReadStream, createWriteStream, unlinkSync } from 'fs';
import yargs from 'yargs';
// tslint:disable-next-line:no-submodule-imports
import { hideBin } from 'yargs/helpers';
import { tmpdir } from 'os';
import { join as pathJoin } from 'path';
import { Readable, Writable } from 'stream';
// tslint:disable-next-line:no-submodule-imports
import * as tty from 'tty';
import { Decrypt, Encrypt } from '../index.js'; // Added .js extension

// Define CustomError interface for augmenting errors with filename
interface CustomError extends NodeJS.ErrnoException {
  filename?: string;
}

/**
 * Shape of arguments after initial parsing by yargs, before custom validation and processing.
 * Optional fields reflect that they may not be present or may be processed into a final form.
 * @internal
 */
interface YargsParsedArgs {
  /** Corresponds to the -e, --encrypt flag. */
  encrypt?: boolean;
  e?: boolean; // Alias for encrypt
  decrypt?: boolean;
  d?: boolean;
  password?: string;
  p?: string;
  output?: string;
  o?: string;
  // Positional arguments from yargs, can be string or number initially
  _?: (string | number)[];
  /** The script name or path. */
  $0?: string; // Script name
}

/**
 * Shape of options after all parsing, validation, and default value processing.
 * These are the options the CLI's `execute` method will directly use.
 * @internal
 */
interface ValidatedCLIOptions {
  /** Whether to perform encryption. Mutually exclusive with `decrypt`. */
  encrypt: boolean;
  /** Whether to perform decryption. Mutually exclusive with `encrypt`. */
  decrypt: boolean;
  /** The password for encryption/decryption. May be undefined if not provided and not prompted yet. */
  password?: string;
  /** The specified output file path. */
  output?: string;
  /** An array of input file paths. Defaults to `['-']` for stdin. */
  input: string[];
}

/**
 * Command Line Interface handler for AESCrypt operations.
 * Encapsulates argument parsing, command execution, and error reporting.
 */
class CLI {
  private options: ValidatedCLIOptions; // Options after parsing, validation, and defaults

  /**
   * Initializes the CLI, parses arguments, and sets up options.
   * Argument parsing and initial validation are handled by yargs.
   */
  constructor() {
    const usageText = `Usage: $0 {-e|-d} [-p <password>] { [-o <output filename>] <file> | <file> [<file> ...] }

Arguments:
  Provide one or more files to be encrypted or decrypted. If you are decrypting a file, it should have a .aes extension.`;

    const examplesText: [string, string][] = [ // Explicitly typed
      ['$0 -e -p foo bar.txt', 'Encrypt bar.txt using password "foo"'],
      ['$0 -d -o baz.txt bar.txt.aes', 'Decrypt bar.txt.aes to baz.txt'],
      ['cat baz.txt | $0 -e -p test > encrypted.aes', 'Encrypt stdin to stdout'],
    ];

    const argv = yargs(hideBin(process.argv))
      .usage(usageText)
      .options({
        encrypt: {
          alias: 'e',
          type: 'boolean',
          description: 'Encrypt the input file(s)',
        },
        decrypt: {
          alias: 'd',
          type: 'boolean',
          description: 'Decrypt the input file(s)',
        },
        password: {
          alias: 'p',
          type: 'string',
          description: 'Use the provided password. Defaults to AESCRYPT_PASSWORD environment variable.',
        },
        output: {
          alias: 'o',
          type: 'string',
          description: 'Specify the output filename. Required if multiple input files or stdin is used for output.',
        },
      })
      .help()
      .alias('help', 'h')
      .version()
      .alias('version', 'v')
      .example(examplesText)
      .wrap(null) // Use full terminal width
      // Removed .config for AESCRYPT_PASSWORD as it's handled post-parse for simplicity
      // and to ensure -p takes precedence correctly.
      .check((currentCheckArgv: YargsParsedArgs) => { // Renamed argv to currentCheckArgv
        // Rule 1 & 2: Mode Exclusivity and Mode Required
        if (currentCheckArgv.encrypt && currentCheckArgv.decrypt) {
          throw new Error('Error: only specify one of -d or -e');
        }
        if (!currentCheckArgv.encrypt && !currentCheckArgv.decrypt) {
          throw new Error('Error: -e or -d not specified');
        }

        // Normalize input to always be an array, defaulting to stdin if empty
        const inputFiles = currentCheckArgv._ && currentCheckArgv._.length > 0 ? currentCheckArgv._.map(String) : ['-'];

        // Rule 3: Output with Multiple Inputs
        if (inputFiles.length > 1 && currentCheckArgv.output) {
          throw new Error('Error: A single output file may not be specified with multiple input files.');
        }
        
        // Rule 4: Stdin with Multiple Inputs
        if (inputFiles.length > 1 && inputFiles.includes('-')) {
          throw new Error('Error: STDIN may not be specified with multiple input files.');
        }

        // Rule 5: Decrypt Extension
        if (currentCheckArgv.decrypt) {
          for (const infile of inputFiles) {
            if (infile !== '-' && !infile.endsWith('.aes')) {
              throw new Error(`Error: input file for decryption '${infile}' doesn't end in .aes`);
            }
          }
        }
        return true; // All checks passed
      })
      .fail((msg, err, _yargsInstance) => { // Prefixed yargsInstance with _
        // Custom failure handler to use existing error method
        if (msg) { // msg is usually the yargs-generated message or the error string from .check()
          this.error(msg);
        } else if (err) { // err is the Error object itself
          this.error(err.message);
        } else {
          // Should not happen, but provide a default
          this.error('An unknown parsing error occurred.');
        }
      })
      .parseSync(); // Use parseSync for constructor context; async execute method will handle async logic


    // Post-processing and setting options for the class instance
    // Type assertion here because yargs.check ensures encrypt/decrypt are mutually exclusive and one is present.
    this.options = {
      encrypt: !!argv.encrypt, // Ensure boolean
      decrypt: !!argv.decrypt, // Ensure boolean
      password: argv.password || process.env.AESCRYPT_PASSWORD, // Default to env var if not provided
      output: argv.output,
      input: (argv._ && argv._.length > 0 ? argv._.map(String) : ['-']), // Ensure input is an array of strings, default to stdin
    };
  }

  public async execute(): Promise<void> {
    const { decrypt, input, output } = this.options;
    let { password } = this.options; // password can be undefined here
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
            // Password will be string by this point due to the !password check and _getPasswordOnStdIn()
            const through = decrypt
              ? new Decrypt(password as string) 
              : new Encrypt(password as string);

            // Centralized error handler for this specific input file's pipeline
            const handleStreamError = (err: Error) => { // Use base Error, cast to CustomError for filename
              const customErr = err as CustomError;
              if (!customErr.filename) {
                customErr.filename = infile === '-' ? 'stdin' : infile;
              }
              reject(customErr);
            };

            from.on('error', handleStreamError);
            through.on('error', handleStreamError);
            to.on('error', handleStreamError);

            from
              .pipe(through)
              .pipe(to)
              .on('finish', resolve);
          })
      )
    )
      .then(() => {
        if (tmpFile) {
          unlinkSync(tmpFile);
        }
      })
      .catch(err => { // Changed 'e' to 'err' for clarity
        if (tmpFile) {
          unlinkSync(tmpFile);
        }
        // Check if it's a NodeJS file system error
        const customErr = err as CustomError; // Cast to CustomError to access potential filename
        if (customErr.code && typeof customErr.code === 'string') {
          const filename = customErr.filename || (customErr.path ? String(customErr.path).split('/').pop() : 'unknown file');
          if (customErr.code === 'ENOENT') {
            this.error(`Error: Input file not found: ${filename}`);
            return;
          }
          if (customErr.code === 'EACCES') {
            this.error(`Error: Permission denied for file: ${filename}`);
            return;
          }
          // For other fs errors, include the code
          this.error(`${customErr.name} (${customErr.code}) for file ${filename}: ${customErr.message.replace(`${customErr.code}: `, '')}`);
          return;
        }
        // For errors from Encrypt/Decrypt or other generic errors
        this.error(customErr.message || `${customErr.name || 'Error'}: An unknown error occurred`);
      });
  }

  /**
   * Prints an error message to stderr and exits the process.
   * @param message - The error message to print.
   * @param code - The exit code (default is 1).
   */
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
    return new Promise((resolve) => {
      const stdin = process.stdin;
      const stdout = process.stdout as tty.WriteStream; // Use tty.WriteStream

      stdin.resume();
      stdin.setEncoding('utf8');
      if (stdin.setRawMode) {
        stdin.setRawMode(true);
      }

      stdout.write(prompt);

      let currentPassword = ''; // Renamed to avoid conflict with outer scope password
      const onData = (b: Buffer) => {
        const ch = b.toString('utf8');

        switch (ch) {
          case '\n': /* falls through */
          case '\r': /* falls through */
          case '\u0004':
            // They've finished typing their password
            stdin.removeListener('data', onData);
            stdout.write('\n');
            if (stdin.setRawMode) {
              stdin.setRawMode(false);
            }
            stdin.pause();
            resolve(currentPassword);
            break;
          case '\u0003':
            // Ctrl-C
            stdout.write('\n');
            process.exit(); // Consider rejecting promise or custom error
            break;
          case BACKSPACE:
            currentPassword = currentPassword.slice(0, currentPassword.length - 1);
            if (stdout.clearLine && stdout.cursorTo) { // Check if methods exist
              stdout.clearLine(0); // 0 for entire line
              stdout.cursorTo(0);
              stdout.write(prompt);
              stdout.write(
                currentPassword
                  .split('')
                  .map(() => '*')
                  .join('')
              );
            }
            break;
          default:
            // More passsword characters
            stdout.write('*');
            currentPassword += ch;
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
