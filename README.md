# node-aescrypt

[![Build Status](https://github.com/judahtanthony/node-aescrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/judahtanthony/node-aescrypt/actions/workflows/ci.yml)
[![Codecov](https://img.shields.io/codecov/c/github/judahtanthony/node-aescrypt.svg)](https://codecov.io/gh/judahtanthony/node-aescrypt)
[![GitHub Stars](https://img.shields.io/github/stars/judahtanthony/node-aescrypt.svg?style=social&logo=github&label=Stars)](https://github.com/judahtanthony/node-aescrypt)

A node implementation of the AES Crypt <https://www.aescrypt.com/> file encryption format.

## How to use this package
This package exposes two different interfaces.  If you are just interested in encrypting secrets on your own workstation, you can use the CLI version.  If you want to use this in an node application, you can import the node library.

### CLI
This simplest way to get started encrypting files is to use NPX to use the executable without necessarily "installing" it.  To encrypt a local file you can simply execute:

```bash
$ npx node-aescrypt -e -p SUPER_SECURE_PASSWORD README.md
```

In this case, I'm encrypting the file README.md.  After this command executes, you will see a new file in your current directory called `README.me.aes`.  To decrypt this file you can use:

```bash
$ npx node-aescrypt -d -p SUPER_SECURE_PASSWORD README.md.aes
```

This will recreate the `README.md` file.

For a little more complicated of an example, you can pipe in data from the command line, so you could archive, compress, and then encrypt a directory like this:

```bash
$ tar -czf - -C src/ . | npx node-aescrypt -e -p SUPER_SECURE_PASSWORD -o my-src.tgz.aes
```

And then if you wanted to reconstitue that directory, you can move the `my-src.tgz.aes` file where ever you need it and execute:

```bash
$ npx node-aescrypt -d -p SUPER_SECURE_PASSWORD -o - my-src.tgz.aes | tar -pxzf -
```

### Library
The primary reason I built this package was actually to integrate it into build systems.  I planned to use the simple AES Crypt <https://www.aescrypt.com/> app to encrypt secrets, and then this library, which is binarily compatibile with it, to decrypt on the fly using ENV variables to store my password.

To use the library version you should import the `Decrypt` or `Encrypt` classes from the module.  These classes implement the node `stream.Transform` interface, so that they can be piped through by any `Readable` and/or `Writable` stream.  So for example if you wanted to encrypt a file you could do this:

```js
import { createReadStream, createWriteStream } from 'fs';
import { Encrypt } from 'node-aescrypt';

const from = createReadStream('somefile.txt');
const to = createWriteStream('somefile.txt.aes');
const through = new Encrypt('SUPER_SECURE_PASSWORD');

from
  .pipe(through)
  .pipe(to)
  .on('error', () => console.error('Oh no!  Something went wrong.'))
  .on('finish', () => console.log('All done.'));
```

For decrypting, it is the exact same process, but make sure the `from` stream is your encrypted file, the `to` stream is to a new file to put the decrypted data into, and you use the `Decrypt` class instead of the `Encrypt` class.

This makes the library very flexible because you can chain these streams in many different ways.  For example, you could pipe the data through a Zlip <https://nodejs.org/api/zlib.html> transformer before you pipe it through the `Encrypt` object.  You could even serve it from a server by piping it into an `http.ServerResponse` <https://nodejs.org/api/http.html#http_class_http_serverresponse> object.
