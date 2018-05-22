import * as assert from "assert";
import { Readable, Writable } from "stream";

import { Encrypt, Decrypt } from "./index";

const getReadable = contents => {
  return new Readable({
    read: function(size) {
      this.push(contents);
      this.push(null);
    }
  });
};
const getWritable = cb => {
  let buffer = Buffer.alloc(0);
  return new Writable({
    write: function(chunk, encoding, callback) {
      buffer =  Buffer.concat([
        buffer,
        chunk,
      ]);
      callback();
    },
    final: function(callback) {
      cb(buffer);
      callback();
    }
  });
};

const KNOWN_TEST_FILE = 'QUVTAgAAGENSRUFURURfQlkAYWVzY3J5cHQgMy4wNQCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIz7OO6zNM6K3hu7TWh/aXzkxPhn/cyCvp+dzNsZilUAxaUWnX4R8CfM0rYXPBOXQ+S0rUf4kAp0us9MEPlNOWSZDgY3tP2/Y2oAm9rOcaWUyWySwDM01UxaDWcLOrp+w0YcH4isUGd2KVIHmmHl68FKwcyY2kikIL+dolT07q6Lo+wL8hVDAmxWNm2Oj23eAk=';
const KNOWN_TEST_PASSWORD = 'test';
const KNOWN_CONTENTS = 'test\n';

describe('Encrypt', function() {
  it ('should create an AES encrypted file', function(done) {
    let s = getReadable(KNOWN_CONTENTS);
    let w = getWritable(contents => {
      assert.equal(contents.slice(0, 3).toString(), 'AES');
      done();
    });
    s.pipe(new Encrypt(KNOWN_TEST_PASSWORD))
     .pipe(w)
     .on('error', done);
  });
});

describe('Decrypt', function() {
  it ('should be able to decrypt an AES encrypted file', function(done) {
    let s = getReadable(Buffer.from(KNOWN_TEST_FILE, 'base64'));
    let w = getWritable(contents => {
      assert.equal(contents.toString(), KNOWN_CONTENTS);
      done();
    });
    s.pipe(new Decrypt(KNOWN_TEST_PASSWORD))
     .pipe(w)
     .on('error', done);
  });
});

describe('Encrypt-Decrypt', function() {
  it ('should get the same contents after decrypting then before encrypting', function(done) {
    let s = getReadable(KNOWN_CONTENTS);
    let w = getWritable(contents => {
      assert.equal(contents.toString(), KNOWN_CONTENTS);
      done();
    });
    s.pipe(new Encrypt(KNOWN_TEST_PASSWORD))
     .pipe(new Decrypt(KNOWN_TEST_PASSWORD))
     .pipe(w)
     .on('error', done);
  });
});
