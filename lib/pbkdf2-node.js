/**
 * Password-Based Key-Derivation Function #2 Node.js implementation.
 *
 * See RFC 2898 for details.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2013 Digital Bazaar, Inc.
 */
import crypto from 'crypto';

/**
 * Derives a key from a password using Node.js crypto library.
 *
 * @param p the password as a binary-encoded string of bytes.
 * @param s the salt as a binary-encoded string of bytes.
 * @param c the iteration count, a positive integer.
 * @param dkLen the intended length, in bytes, of the derived key,
 *          (max: 2^32 - 1) * hash length of the PRF.
 * @param [md] the message digest (or algorithm identifier as a string) to use
 *          in the PRF, defaults to SHA-1.
 * @param [callback(err, key)] presence triggers asynchronous version, called
 *          once the operation completes.
 *
 * @return the derived key, as a binary-encoded string of bytes, for the
 *           synchronous version (if no callback is specified). `null` if
 *           not supported and the pure JS fallback should be used.
 */
export function pbkdf2(p, s, c, dkLen, md, callback) {
  if(typeof md === 'function') {
    callback = md;
    md = null;
  }

  // use native implementation if possible and not disabled, note that
  // some node versions only support SHA-1, others allow digest to be changed
  if(crypto.pbkdf2 && (md === null || typeof md !== 'object') &&
    (crypto.pbkdf2Sync.length > 4 || (!md || md === 'sha1'))) {
    if(typeof md !== 'string') {
      // default prf to SHA-1
      md = 'sha1';
    }
    p = Buffer.from(p, 'binary');
    s = Buffer.from(s, 'binary');
    if(!callback) {
      if(crypto.pbkdf2Sync.length === 4) {
        return crypto.pbkdf2Sync(p, s, c, dkLen).toString('binary');
      }
      return crypto.pbkdf2Sync(p, s, c, dkLen, md).toString('binary');
    }
    if(crypto.pbkdf2Sync.length === 4) {
      return crypto.pbkdf2(p, s, c, dkLen, function(err, key) {
        if(err) {
          return callback(err);
        }
        callback(null, key.toString('binary'));
      });
    }
    return crypto.pbkdf2(p, s, c, dkLen, md, function(err, key) {
      if(err) {
        return callback(err);
      }
      callback(null, key.toString('binary'));
    });
  }
  // unsupported
  if(callback) {
    return callback(null, null);
  }
  return null;
}
