/**
 * Utility functions for web applications.
 * 
 * @author Dave Longley
 *
 * Copyright (c) 2010 Digital Bazaar, Inc. All rights reserved.
 */
(function()
{
   /**
    * The util namespace.
    */
   var util = {};
   
   /**
    * Creates a buffer that stores bytes.
    * 
    * @param b the bytes to wrap (as a string) (optional).
    */
   util.createBuffer = function(b)
   {
      var buf =
      {
         // the data in this buffer.
         data: b || new String(),
         // the pointer for reading from this buffer.
         read: 0
      };
      
      /**
       * Gets the number of bytes in this buffer.
       * 
       * @return the number of bytes in this buffer.
       */
      buf.length = function()
      {
         return buf.data.length - buf.read;
      };
      
      /**
       * Puts a byte in this buffer.
       * 
       * @param b the byte to put.
       */
      buf.putByte = function(b)
      {
         buf.data += String.fromCharCode(b);
      };
      
      /**
       * Puts a byte in this buffer N times.
       * 
       * @param b the byte to put.
       * @param n the number of bytes of value b to put.
       */
      buf.fillWithByte = function(b, n)
      {
         b = String.fromCharCode(b);
         var d = buf.data;
         while(n > 0)
         {
            if(n & 1)
            {
               d += b;
            }
            n >>>= 1;
            if(n > 0)
            {
               b += b;
            }
         }
         buf.data = d;
      };
      
      /**
       * Puts bytes in this buffer.
       * 
       * @param bytes the bytes (as a string) to put.
       */
      buf.putBytes = function(bytes)
      {
         buf.data += bytes;
      };
      
      /**
       * Puts a 16-bit integer in this buffer in big-endian order.
       * 
       * @param i the 16-bit integer.
       */
      buf.putInt16 = function(i)
      {
         buf.data +=
            String.fromCharCode(i >> 8 & 0xFF) +
            String.fromCharCode(i & 0xFF);
      };
      
      /**
       * Puts a 24-bit integer in this buffer in big-endian order.
       * 
       * @param i the 24-bit integer.
       */
      buf.putInt24 = function(i)
      {
         buf.data +=
            String.fromCharCode(i >> 16 & 0xFF) +
            String.fromCharCode(i >> 8 & 0xFF) +
            String.fromCharCode(i & 0xFF);
      };
      
      /**
       * Puts a 32-bit integer in this buffer in big-endian order.
       * 
       * @param i the 32-bit integer.
       */
      buf.putInt32 = function(i)
      {
         buf.data +=
            String.fromCharCode(i >> 24 & 0xFF) +
            String.fromCharCode(i >> 16 & 0xFF) +
            String.fromCharCode(i >> 8 & 0xFF) +
            String.fromCharCode(i & 0xFF);
      };
      
      /**
       * Puts a 16-bit integer in this buffer in little-endian order.
       * 
       * @param i the 16-bit integer.
       */
      buf.putInt16Le = function(i)
      {
         buf.data +=
            String.fromCharCode(i & 0xFF) +
            String.fromCharCode(i >> 8 & 0xFF);
      };
      
      /**
       * Puts a 24-bit integer in this buffer in little-endian order.
       * 
       * @param i the 24-bit integer.
       */
      buf.putInt24Le = function(i)
      {
         buf.data +=
            String.fromCharCode(i & 0xFF) +
            String.fromCharCode(i >> 8 & 0xFF) +
            String.fromCharCode(i >> 16 & 0xFF);
      };
      
      /**
       * Puts a 32-bit integer in this buffer in little-endian order.
       * 
       * @param i the 32-bit integer.
       */
      buf.putInt32Le = function(i)
      {
         buf.data +=
            String.fromCharCode(i & 0xFF) +
            String.fromCharCode(i >> 8 & 0xFF) +
            String.fromCharCode(i >> 16 & 0xFF) +
            String.fromCharCode(i >> 24 & 0xFF);
      };
      
      /**
       * Puts an n-bit integer in this buffer in big-endian order.
       * 
       * @param i the n-bit integer.
       * @param n the number of bits in the integer.
       */
      buf.putInt = function(i, n)
      {
         do
         {
            n -= 8;
            buf.data += String.fromCharCode((i >> n) & 0xFF);
         }
         while(n > 0);
      };
      
      /**
       * Puts the given buffer into this buffer.
       * 
       * @param buffer the buffer to put into this one.
       */
      buf.putBuffer = function(buffer)
      {
         buf.data += buffer.getBytes();
      };
      
      /**
       * Gets a byte from this buffer and advances the read pointer by 1.
       * 
       * @return the byte.
       */
      buf.getByte = function()
      {
         return buf.data.charCodeAt(buf.read++);
      };
      
      /**
       * Gets a uint16 from this buffer in big-endian order and advances the
       * read pointer by 2.
       * 
       * @return the uint16.
       */
      buf.getInt16 = function()
      {
         return (
            buf.data.charCodeAt(buf.read++) << 8 ^
            buf.data.charCodeAt(buf.read++));
      };
      
      /**
       * Gets a uint24 from this buffer in big-endian order and advances the
       * read pointer by 3.
       * 
       * @return the uint24.
       */
      buf.getInt24 = function()
      {
         return (
            buf.data.charCodeAt(buf.read++) << 16 ^
            buf.data.charCodeAt(buf.read++) << 8 ^
            buf.data.charCodeAt(buf.read++));
      };
      
      /**
       * Gets a uint32 from this buffer in big-endian order and advances the
       * read pointer by 4.
       * 
       * @return the word.
       */
      buf.getInt32 = function()
      {
         return (
            buf.data.charCodeAt(buf.read++) << 24 ^
            buf.data.charCodeAt(buf.read++) << 16 ^
            buf.data.charCodeAt(buf.read++) << 8 ^
            buf.data.charCodeAt(buf.read++));
      };
      
      /**
       * Gets a uint16 from this buffer in little-endian order and advances the
       * read pointer by 2.
       * 
       * @return the uint16.
       */
      buf.getInt16Le = function()
      {
         return (
            buf.data.charCodeAt(buf.read++) ^
            buf.data.charCodeAt(buf.read++) << 8);
      };
      
      /**
       * Gets a uint24 from this buffer in little-endian order and advances the
       * read pointer by 3.
       * 
       * @return the uint24.
       */
      buf.getInt24Le = function()
      {
         return (
            buf.data.charCodeAt(buf.read++) ^
            buf.data.charCodeAt(buf.read++) << 8 ^
            buf.data.charCodeAt(buf.read++) << 16);
      };
      
      /**
       * Gets a uint32 from this buffer in little-endian order and advances the
       * read pointer by 4.
       * 
       * @return the word.
       */
      buf.getInt32Le = function()
      {
         return (
            buf.data.charCodeAt(buf.read++) ^
            buf.data.charCodeAt(buf.read++) << 8 ^
            buf.data.charCodeAt(buf.read++) << 16 ^
            buf.data.charCodeAt(buf.read++) << 24);
      };
      
      /**
       * Gets an n-bit integer from this buffer in big-endian order and
       * advances the read pointer by n/8.
       * 
       * @param n the number of bits in the integer.
       * 
       * @return the integer.
       */
      buf.getInt = function(n)
      {
         var rval = 0;
         do
         {
            rval = (rval << n) + buf.data.charCodeAt(buf.read++);
            n -= 8;
         }
         while(n > 0);
         return rval;
      };
      
      /**
       * Reads bytes out into a string and clears them from the buffer.
       * 
       * @param count the number of bytes to read, undefined, null or 0
       *           for all.
       * 
       * @return a string of bytes.
       */
      buf.getBytes = function(count)
      {
         var rval;
         if(count)
         {
            // read count bytes
            count = Math.min(buf.length(), count);
            rval = buf.data.slice(buf.read, buf.read + count);
            buf.read += count;
         }
         else if(count === 0)
         {
            rval = '';
         }
         else
         {
            // read all bytes, optimize to only copy when needed
            rval = (buf.read === 0) ? buf.data : buf.data.slice(buf.read);
            buf.clear();
         }
         return rval;
      };
      
      /**
       * Gets a string of all the bytes without modifying the read
       * pointer.
       * 
       * @return an array of bytes.
       */
      buf.bytes = function()
      {
         return buf.data.slice(buf.read);
      };
      
      /**
       * Gets a byte at the given index without modifying the read
       * pointer.
       * 
       * @param i the byte index.
       * 
       * @return the byte.
       */
      buf.at = function(i)
      {
         return buf.data.charCodeAt(buf.read + i);
      };
      
      /**
       * Gets the last byte without modifying the read pointer.
       * 
       * @return the last byte.
       */
      buf.last = function()
      {
         return buf.data.charCodeAt(buf.data.length - 1);
      };
      
      /**
       * Creates a copy of this buffer.
       * 
       * @return the copy.
       */
      buf.copy = function()
      {
         var c = util.createBuffer(buf.data);
         c.read = buf.read;
         return c;
      };
      
      /**
       * Compacts this buffer.
       */
      buf.compact = function()
      {
         if(buf.read > 0)
         {
            buf.data = buf.data.slice(buf.read);
            buf.read = 0;
         }
      };
      
      /**
       * Clears this buffer.
       */
      buf.clear = function()
      {
         buf.data = new String();
         buf.read = 0;
      };
      
      /**
       * Shortens this buffer by triming bytes off of the end of this
       * buffer.
       * 
       * @param count the number of bytes to trim off.
       */
      buf.truncate = function(count)
      {
         var len = Math.max(0, buf.length() - count);
         buf.data = buf.data.substr(buf.read, len);
         buf.read = 0;
      };
      
      /**
       * Converts this buffer to a hexadecimal string.
       * 
       * @return a hexadecimal string.
       */
      buf.toHex = function()
      {
         var rval = '';
         var len = buf.length();
         for(var i = buf.read; i < len; ++i)
         {
            var b = buf.data.charCodeAt(i);
            if(b < 16)
            {
               rval += '0';
            }
            rval += b.toString(16);
         }
         return rval;
      };
      
      return buf;
   };
   
   /**
    * Fills a string with a particular value. If you want the string to be
    * a byte string, pass in String.fromCharCode(theByte).
    * 
    * @param c the character to fill the string with, use String.fromCharCode
    *           to fill the string with a byte value.
    * @param n the number of characters of value c to fill with.
    * 
    * @return the filled string.
    */
   util.fillString = function(c, n)
   {
      var s = '';
      while(n > 0)
      {
         if(n & 1)
         {
            s += c;
         }
         n >>>= 1;
         if(n > 0)
         {
            c += c;
         }
      }
      return s;
   };
   
   /**
    * Performs a per byte XOR between two byte strings and returns the result
    * as a string of bytes.
    * 
    * @param s1 first string of bytes.
    * @param s2 second string of bytes.
    * @param n the number of bytes to XOR.
    * 
    * @return the XOR'd result.
    */
   util.xorBytes = function(s1, s2, n)
   {
      var s3 = '';
      var b = '';
      var t = '';
      var i = 0;
      var c = 0;
      for(; n > 0; --n, ++i)
      {
         b = s1.charCodeAt(i) ^ s2.charCodeAt(i);
         if(c >= 10)
         {
            s3 += t;
            t = '';
            c = 0;
         }
         t += String.fromCharCode(b);
         ++c;
      }
      s3 += t;
      return s3;
   };
   
   /**
    * Converts a hex string into a string of bytes.
    * 
    * @param hex the hexadecimal string to convert.
    * 
    * @return the string of bytes.
    */
   util.hexToBytes = function(hex)
   {
      var rval = '';
      var i = 0;
      if(hex.length & 1 == 1)
      {
         // odd number of characters, convert first character alone
         i = 1;
         rval += String.fromCharCode(parseInt(hex[0], 16));
      }
      // convert 2 characters (1 byte) at a time
      for(; i < hex.length; i += 2)
      {
         rval += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
      }
      return rval;
   };
   
   /**
    * Converts a byte string into a string of hexadecimal characters.
    * 
    * @param bytes the byte string to convert.
    * 
    * @return the string of hexadecimal characters.
    */
   util.bytesToHex = function(bytes)
   {
      return util.createBuffer(bytes).toHex();
   };
   
   // base64 characters, reverse mapping
   var _base64 =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
   var _base64Idx = [
   /* 43 -43 = 0*/
   /* '+',  1,  2,  3,'/' */
       62, -1, -1, -1, 63,

   /* '0','1','2','3','4','5','6','7','8','9' */
       52, 53, 54, 55, 56, 57, 58, 59, 60, 61,

   /* 15, 16, 17,'=', 19, 20, 21 */
      -1, -1, -1, 64, -1, -1, -1,

   /* 65 - 43 = 22*/
   /*'A','B','C','D','E','F','G','H','I','J','K','L','M', */
       0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,

   /* 'N','O','P','Q','R','S','T','U','V','W','X','Y','Z' */
       13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,

   /* 91 - 43 = 48 */
   /* 48, 49, 50, 51, 52, 53 */
      -1, -1, -1, -1, -1, -1,

   /* 97 - 43 = 54*/
   /* 'a','b','c','d','e','f','g','h','i','j','k','l','m' */
       26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,

   /* 'n','o','p','q','r','s','t','u','v','w','x','y','z' */
       39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
   ];
   
   /**
    * Base64 encodes a string of bytes.
    * 
    * @param input the string of bytes to encode.
    * 
    * @return the base64-encoded output.
    */
   util.encode64 = function(input)
   {
      var output = new String();
      var chr1, chr2, chr3;
      var i = 0;
      while(i < input.length)
      {
         chr1 = input.charCodeAt(i++);
         chr2 = input.charCodeAt(i++);
         chr3 = input.charCodeAt(i++);
         
         // encode 4 character group
         output += _base64.charAt(chr1 >> 2);
         output += _base64.charAt(((chr1 & 3) << 4) | (chr2 >> 4));
         if(isNaN(chr2))
         {
            output += '==';
         }
         else
         {
            output += _base64.charAt(((chr2 & 15) << 2) | (chr3 >> 6));
            output += isNaN(chr3) ? '=' : _base64.charAt(chr3 & 63);
         }
      }
      
      return output;      
   };
   
   /**
    * Base64 decodes a string into a string of bytes.
    * 
    * @param input the base64-encoded input.
    * 
    * @return the raw bytes.
    */
   util.decode64 = function(input)
   {
      // remove all non-base64 characters
      input = input.replace(/[^A-Za-z0-9\+\/\=]/g, '');
      
      var output = new String();
      var enc1, enc2, enc3, enc4;
      var i = 0;
      
      while(i < input.length)
      {
         enc1 = _base64Idx[input.charCodeAt(i++) - 43];
         enc2 = _base64Idx[input.charCodeAt(i++) - 43];
         enc3 = _base64Idx[input.charCodeAt(i++) - 43];
         enc4 = _base64Idx[input.charCodeAt(i++) - 43];
         
         output += String.fromCharCode((enc1 << 2) | (enc2 >> 4));
         if(enc3 !== 64)
         {
            // decoded at least 2 bytes
            output += String.fromCharCode(((enc2 & 15) << 4) | (enc3 >> 2));
            if(enc4 !== 64)
            {
               // decoded 3 bytes
               output += String.fromCharCode(((enc3 & 3) << 6) | enc4);
            }
         }
      }
      
      return output;
   };
   
   /**
    * Deflates the given data using a flash interface.
    * 
    * @param api the flash interface.
    * @param bytes the data.
    * @param raw true to return only raw deflate data, false to include zlib
    *           header and trailer.
    * 
    * @return the deflated data as a string.
    */
   util.deflate = function(api, bytes, raw)
   {
      bytes = util.decode64(api.deflate(util.encode64(bytes)).rval);
      
      // strip zlib header and trailer if necessary
      if(raw)
      {
         // zlib header is 2 bytes (CMF,FLG) where FLG indicates that
         // there is a 4-byte DICT (alder-32) block before the data if
         // its 5th bit is set
         var start = 2;
         var flg = bytes.charCodeAt(1);
         if(flg & 0x20)
         {
            start = 6;
         }
         // zlib trailer is 4 bytes of adler-32
         bytes = bytes.substring(start, bytes.length - 4);
      }
      
      return bytes;
   };
   
   /**
    * Inflates the given data using a flash interface.
    * 
    * @param api the flash interface.
    * @param bytes the data.
    * @param raw true if the incoming data has no zlib header or trailer and
    *           is raw DEFLATE data.
    * 
    * @return the inflated data as a string, null on error.
    */
   util.inflate = function(api, bytes, raw)
   {
      // TODO: add zlib header and trailer if necessary/possible
      var rval = api.inflate(util.encode64(bytes)).rval;
      return (rval === null) ? null : util.decode64(rval);
   };
   
   /**
    * Stores an item on local disk using a flash interface.
    * 
    * @param api the flash interface.
    * @param id the storage ID to use.
    * @param key the key for the item.
    * @param data the data for the item (any javascript object/primitive).
    */
   util.setItem = function(api, id, key, data)
   {
      // json-encode and then store data
      var d = JSON.stringify(data);
      var rval = api.setItem(id, key, util.encode64(d));
      if(rval.rval !== true)
      {
         throw rval.error;
      }
   };
   
   /**
    * Gets an item on local disk using a flash interface.
    * 
    * @param api the flash interface.
    * @param id the storage ID to use.
    * @param key the key for the item.
    * 
    * @return the item.
    */
   util.getItem = function(api, id, key)
   {
      // get the base64-encoded data
      var rval = api.getItem(id, key);
      if(rval.rval === null && rval.error)
      {
         throw rval.error;
      }
      
      if(rval.rval === null)
      {
         // no error, but no item
         rval = null;
      }
      else
      {
         // base64-decode and return json-decoded data
         rval = JSON.parse(util.decode64(rval.rval));
      }
      
      return rval;
   };
   
   /**
    * Removes an item on local disk using a flash interface.
    * 
    * @param api the flash interface.
    * @param id the storage ID to use.
    * @param key the key for the item.
    */
   util.removeItem = function(api, id, key)
   {
      var rval = api.removeItem(id, key);
      if(rval.rval !== true && rval.error)
      {
         throw rval.error;
      }
   };
   
   /**
    * Clears the local disk storage identified by the given ID using a
    * flash interface.
    * 
    * @param api the flash interface.
    * @param id the storage ID to use.
    */
   util.clearItems = function(api, id)
   {
      var rval = api.clearItems(id);
      if(rval.rval !== true)
      {
         throw rval.error;
      }
   };
   
   /* Storage for query variables */
   var _queryVariables = null;
   
   /**
    * Returns the window location query variables. Query is parsed on the first
    * call and the same object is returned on subsequent calls. The mapping
    * is from keys to an array of values. Parameters without values will have
    * an object key set but no value added to the value array. Values are
    * unescaped.
    *
    * ...?k1=v1&k2=v2:
    * {
    *   "k1": ["v1"],
    *   "k2": ["v2"]
    * }
    *
    * ...?k1=v1&k1=v2:
    * {
    *   "k1": ["v1", "v2"]
    * }
    *
    * ...?k1=v1&k2:
    * {
    *   "k1": ["v1"],
    *   "k2": []
    * }
    *
    * ...?k1=v1&k1:
    * {
    *   "k1": ["v1"]
    * }
    *
    * ...?k1&k1:
    * {
    *   "k1": []
    * }
    *
    * @param query the query string to parse (optional, default to cached
    *        results from parsing window location search query).
    *
    * @return object mapping keys to variables. 
    */
   util.getQueryVariables = function(query)
   {
      var parse = function(q)
      {
         var rval = {};
         var kvpairs = q.split('&');
         for (var i = 0; i < kvpairs.length; i++)
         {
            var pos = kvpairs[i].indexOf('=');
            var key;
            var val;
            if (pos > 0)
            {
               key = kvpairs[i].substring(0,pos);
               val = kvpairs[i].substring(pos+1);
            }
            else
            {
               key = kvpairs[i];
               val = null;
            }
            if(!(key in rval))
            {
               rval[key] = [];
            }
            if(val !== null)
            {
               rval[key].push(unescape(val));
            }
         }
         return rval;
      };
      
      var rval;
      if(typeof(query) === 'undefined')
      {
         // cache and use window search query
         if(_queryVariables === null)
         {
            _queryVariables = parse(window.location.search.substring(1));
         }
         rval = _queryVariables;
      }
      else
      {
         // parse given query
         rval = parse(query);
      }
      return rval;
   };

   /**
    * Parses a fragment into a path and query. This method will take a URI
    * fragment and break it up as if it were the main URI. For example:
    *    /bar/baz?a=1&b=2
    * results in:
    *    {
    *       path: ["bar", "baz"],
    *       query: {"k1": ["v1"], "k2": ["v2"]}
    *    }
    * 
    * @return object with a path array and query object.
    */
   util.parseFragment = function(fragment)
   {
      // default to whole fragment
      var fp = fragment;
      var fq = '';
      // split into path and query if possible at the first '?'
      var pos = fragment.indexOf('?');
      if(pos > 0)
      {
         fp = fragment.substring(0,pos);
         fq = fragment.substring(pos+1);
      }
      // split path based on '/' and ignore first element if empty
      var path = fp.split('/');
      if(path.length > 0 && path[0] == '')
      {
         path.shift();
      }
      // convert query into object
      var query = (fq == '') ? {} : util.getQueryVariables(fq);
      
      return {
         pathString: fp,
         queryString: fq,
         path: path,
         query: query
      };
   };
   
   /**
    * Makes a request out of a URI-like request string. This is intended to
    * be used where a fragment id (after a URI '#') is parsed as a URI with
    * path and query parts. The string should have a path beginning and
    * delimited by '/' and optional query parameters following a '?'. The
    * query should be a standard URL set of key value pairs delimited by
    * '&'. For backwards compatibility the initial '/' on the path is not
    * required. The request object has the following API, (fully described
    * in the method code):
    *    {
    *       path: <the path string part>.
    *       query: <the query string part>,
    *       getPath(i): get part or all of the split path array,
    *       getQuery(k, i): get part or all of a query key array,
    *       getQueryLast(k, _default): get last element of a query key array.
    *    }
    * 
    * @return object with request parameters.
    */
   util.makeRequest = function(reqString)
   {
      var frag = util.parseFragment(reqString);
      var req =
      {
         // full path string
         path: frag.pathString,
         // full query string
         query: frag.queryString,
         /**
          * Get path or element in path.
          * 
          * @param i optional path index.
          * 
          * @return path or part of path if i provided.
          */
         getPath: function(i)
         {
            return (typeof(i) === 'undefined') ? frag.path : frag.path[i];
         },
         /**
          * Get query, values for a key, or value for a key index.
          * 
          * @param k optional query key.
          * @param i optional query key index.
          * 
          * @return query, values for a key, or value for a key index.
          */
         getQuery: function(k, i)
         {
            var rval;
            if(typeof(k) === 'undefined')
            {
               rval = frag.query;
            }
            else
            {
               rval = frag.query[k];
               if(rval && typeof(i) !== 'undefined')
               {
                  rval = rval[i];
               }
            }
            return rval;
         },
         getQueryLast: function(k, _default)
         {
            var rval;
            var vals = req.getQuery(k);
            if(vals)
            {
               rval = vals[vals.length - 1];
            }
            else
            {
               rval = _default;
            }
            return rval;
         }
      };
      return req;
   };
   
   /**
    * Makes a URI out of a path, an object with query parameters, and a
    * fragment. Uses jQuery.param() internally for query string creation.
    * If the path is an array, it will be joined with '/'.
    * 
    * @param path string path or array of strings.
    * @param query object with query parameters. (optional)
    * @param fragment fragment string. (optional)
    * 
    * @return string object with request parameters.
    */
   util.makeLink = function(path, query, fragment)
   {
      // join path parts if needed
      path = jQuery.isArray(path) ? path.join('/') : path;
       
      var qstr = jQuery.param(query || {});
      fragment = fragment || '';
      return path +
         ((qstr.length > 0) ? ('?' + qstr) : '') +
         ((fragment.length > 0) ? ('#' + fragment) : '');
   };
   
   /**
    * Follows a path of keys deep into an object hierarchy and set a value.
    * If a key does not exist or it's value is not an object, create an
    * object in it's place. This can be destructive to a object tree if
    * leaf nodes are given as non-final path keys.
    * Used to avoid exceptions from missing parts of the path.
    *
    * @param object the starting object.
    * @param keys an array of string keys.
    * @param value the value to set.
    */
   util.setPath = function(object, keys, value)
   {
      // need to start at an object
      if(typeof(object) === 'object' && object !== null)
      {
         var i = 0;
         var len = keys.length;
         while(i < len)
         {
            var next = keys[i++];
            if(i == len)
            {
               // last
               object[next] = value;
            }
            else
            {
               // more
               var hasNext = (next in object);
               if(!hasNext ||
                  (hasNext && typeof(object[next]) !== 'object') ||
                  (hasNext && object[next] === null))
               {
                  object[next] = {};
               }
               object = object[next];
            }
         }
      }
   };
   
   /**
    * Follows a path of keys deep into an object hierarchy and return a value.
    * If a key does not exist, create an object in it's place.
    * Used to avoid exceptions from missing parts of the path.
    *
    * @param object the starting object.
    * @param keys an array of string keys.
    * @param _default value to return if path not found.
    * @return the value at the path if found, else default if given, else
    *         undefined.
    */
   util.getPath = function(object, keys, _default)
   {
      var i = 0;
      var len = keys.length;
      var hasNext = true;
      while(hasNext && i < len &&
         typeof(object) === 'object' && object !== null)
      {
         var next = keys[i++];
         hasNext = next in object;
         if(hasNext)
         {
            object = object[next];
         }
      }
      return (hasNext ? object : _default);
   };
   
   /**
    * Follow a path of keys deep into an object hierarchy and delete the
    * last one. If a key does not exist, do nothing.
    * Used to avoid exceptions from missing parts of the path.
    *
    * @param object the starting object.
    * @param keys an array of string keys.
    */
   util.deletePath = function(object, keys)
   {
      // need to start at an object
      if(typeof(object) === 'object' && object !== null)
      {
         var i = 0;
         var len = keys.length;
         var hasNext = true;
         while(i < len)
         {
            var next = keys[i++];
            if(i == len)
            {
               // last
               delete object[next];
            }
            else
            {
               // more
               if(!(next in object) ||
                  (typeof(object[next]) !== 'object') ||
                  (object[next] === null))
               {
                  break;
               }
               object = object[next];
            }
         }
      }
   };
   
   /**
    * Check if an object is empty.
    *
    * Taken from:
    * http://stackoverflow.com/questions/679915/how-do-i-test-for-an-empty-javascript-object-from-json/679937#679937
    *
    * @param object the object to check.
    */
   util.isEmpty = function(obj)
   {
      for(var prop in obj)
      {
         if(obj.hasOwnProperty(prop))
         {
            return false;
         }
      }
      return true;
   };
   
   /**
    * Format with simple printf-style interpolation.
    *
    * %%: literal '%'
    * %s,%o: convert next argument into a string.
    *
    * @param format the string to format.
    * @param ... arguments to interpolate into the format string.
    */
   util.format = function(format)
   {
      var re = /%./g;
      // current match
      var match;
      // current part
      var part;
      // current arg index
      var argi = 0;
      // collected parts to recombine later
      var parts = [];
      // last index found
      var last = 0;
      // loop while matches remain
      while((match = re.exec(format)))
      {
         part = format.substring(last, re.lastIndex - 2);
         // don't add empty strings (ie, parts between %s%s)
         if(part.length > 0)
         {
            parts.push(part);
         }
         last = re.lastIndex;
         // switch on % code
         var code = match[0][1];
         switch(code)
         {
            case 's':
            case 'o':
               // check if enough arguments were given
               if(argi < arguments.length)
               {
                  parts.push(arguments[argi++ + 1]);
               }
               else
               {
                  parts.push('<?>');
               }
               break;
            // FIXME: do proper formating for numbers, etc
            //case 'f':
            //case 'd':
            case '%':
               parts.push('%');
               break;
            default:
               parts.push('<%' + code + '?>');
         }
      }
      // add trailing part of format string
      parts.push(format.substring(last));
      return parts.join('');
   };
   
   /**
    * Formats a number.
    *
    * http://snipplr.com/view/5945/javascript-numberformat--ported-from-php/
    */
   util.formatNumber = function(number, decimals, dec_point, thousands_sep)
   {
       // http://kevin.vanzonneveld.net
       // +   original by: Jonas Raoni Soares Silva (http://www.jsfromhell.com)
       // +   improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
       // +     bugfix by: Michael White (http://crestidg.com)
       // +     bugfix by: Benjamin Lupton
       // +     bugfix by: Allan Jensen (http://www.winternet.no)
       // +    revised by: Jonas Raoni Soares Silva (http://www.jsfromhell.com)    
       // *     example 1: number_format(1234.5678, 2, '.', '');
       // *     returns 1: 1234.57 
    
       var n = number, c = isNaN(decimals = Math.abs(decimals)) ? 2 : decimals;
       var d = dec_point === undefined ? ',' : dec_point;
       var t = thousands_sep === undefined ?
          '.' : thousands_sep, s = n < 0 ? '-' : '';
       var i = parseInt(n = Math.abs(+n || 0).toFixed(c)) + '';
       var j = (i.length > 3) ? i.length % 3 : 0;
       return s + (j ? i.substr(0, j) + t : '') +
          i.substr(j).replace(/(\d{3})(?=\d)/g, '$1' + t) +
          (c ? d + Math.abs(n - i).toFixed(c).slice(2) : '');
   };
   
   /**
    * Formats a byte size.
    * 
    * http://snipplr.com/view/5949/format-humanize-file-byte-size-presentation-in-javascript/
    */
   util.formatSize = function(size)
   {
      if(size >= 1073741824)
      {
         size = util.formatNumber(size / 1073741824, 2, '.', '') + ' GiB';
      }
      else
      {
         if(size >= 1048576)
         {
            size = util.formatNumber(size / 1048576, 2, '.', '') + ' MiB';
         }
         else if (size >= 1024)
         {
            size = util.formatNumber(size / 1024, 0) + ' KiB';
         }
         else
         {
            size = util.formatNumber(size, 0) + ' bytes';
         }
      }
      return size;
   };
   
   /**
    * The crypto namespace and util API.
    */
   window.forge = window.forge || {};
   window.forge.util = util;
})();
