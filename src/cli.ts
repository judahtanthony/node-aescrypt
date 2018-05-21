import { createReadStream, createWriteStream } from "fs";
import { Readable, Writable } from "stream";
import { Encrypt, Decrypt } from "./index";

const OPTION_DEFINITIONS = [
  { name: 'encrypt', alias: 'e', type: Boolean },
  { name: 'decrypt', alias: 'd', type: Boolean },
  { name: 'password', alias: 'p', type: String },
  { name: 'output', alias: 'o', type: String },
  { name: 'input', alias: 'i', type: String, multiple: true, defaultOption: true, defaultValue: '-' },
];

const CLI_HELP = 'usage: aescrypt {-e|-d} [-p <password>] { [-o <output filename>] <file> | <file> [<file> ...] }';

interface Options {
  encrypt?:boolean;
  decrypt?:boolean;
  password?:string;
  output?:string;
  input?:string[];
}

class CLI {
  options: Options;
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
  execute ():void {
    const { encrypt, decrypt, input, output, password } = this.options;
    // This would be a great use of async.
    Promise.all(input.map(infile => new Promise((resolve, reject) => {
      const from = this._getFromStream(infile);
      const to = this._getToStream(infile, output, decrypt);
      const through = decrypt ? new Decrypt(password) : new Encrypt(password);
      from.pipe(through)
          .pipe(to)
          .on('error', reject)
          .on('finish', resolve);
    })))
    .catch(e => this.error(e.name + ': ' + e.message));
  }
  _getFromStream (input:string):Readable {
    return input == '-' ? process.stdin : createReadStream(input);
  }
  _getToStream (input:string, output?:string, decrypt?:boolean):Writable {
    if (output == '-' || (input == '-' && !output)) {
      return process.stdout;
    }
    let outfile = output;
    if (!outfile) {
      outfile = decrypt ? input.substr(0, input.length - 4) : input + '.aes';
    }
    return createWriteStream(outfile);
  }
  error (message:string, code:number=1):void {
    console.error(message);
    console.info("\n" + CLI_HELP);
    process.exit(code);
  }
}

let app = new CLI();
app.execute();
