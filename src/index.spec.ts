import * as assert from "assert";
import { Readable, Writable } from "stream";

import { Encrypt, Decrypt } from "./index";

describe('Encrypt', () => {
  it ('should create an AES encrypted file', () => {
    let s = new Readable({
      read: function(size) {
        this.push('test');
        this.push(null);
      }
    });
    // This should be done better, with some kind of
    // accumulator that only runs after the stream is
    // closed.
    let w = new Writable({
      write: function(chunk, encoding, callback) {
        assert.equal(chunk.slice(0, 3).toString(), 'AES');
      }
    });
    s.pipe(new Encrypt('test')).pipe(w);
  });
});
