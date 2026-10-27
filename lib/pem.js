/**
 * Javascript implementation of basic PEM (Privacy Enhanced Mail) algorithms.
 *
 * See: RFC 1421.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2013-2014 Digital Bazaar, Inc.
 *
 * A Forge PEM object has the following fields:
 *
 * type: identifies the type of message (eg: "RSA PRIVATE KEY").
 *
 * procType: identifies the type of processing performed on the message,
 *   it has two subfields: version and type, eg: 4,ENCRYPTED.
 *
 * contentDomain: identifies the type of content in the message, typically
 *   only uses the value: "RFC822".
 *
 * dekInfo: identifies the message encryption algorithm and mode and includes
 *   any parameters for the algorithm, it has two subfields: algorithm and
 *   parameters, eg: DES-CBC,F8143EDE5960C597.
 *
 * headers: contains all other PEM encapsulated headers -- where order is
 *   significant (for pairing data like recipient ID + key info).
 *
 * body: the binary-encoded body.
 */
var forge = require('./forge');
require('./util');

// shortcut for pem API
var pem = module.exports = forge.pem = forge.pem || {};

/**
 * Encodes (serializes) the given PEM object.
 *
 * @param msg the PEM message object to encode.
 * @param options the options to use:
 *          maxline the maximum characters per line for the body, (default: 64).
 *
 * @return the PEM-formatted string.
 */
pem.encode = function(msg, options) {
  options = options || {};
  var rval = '-----BEGIN ' + msg.type + '-----\r\n';

  // encode special headers
  var header;
  if(msg.procType) {
    header = {
      name: 'Proc-Type',
      values: [String(msg.procType.version), msg.procType.type]
    };
    rval += foldHeader(header);
  }
  if(msg.contentDomain) {
    header = {name: 'Content-Domain', values: [msg.contentDomain]};
    rval += foldHeader(header);
  }
  if(msg.dekInfo) {
    header = {name: 'DEK-Info', values: [msg.dekInfo.algorithm]};
    if(msg.dekInfo.parameters) {
      header.values.push(msg.dekInfo.parameters);
    }
    rval += foldHeader(header);
  }

  if(msg.headers) {
    // encode all other headers
    for(var i = 0; i < msg.headers.length; ++i) {
      rval += foldHeader(msg.headers[i]);
    }
  }

  // terminate header
  if(msg.procType) {
    rval += '\r\n';
  }

  // add body
  rval += forge.util.encode64(msg.body, options.maxline || 64) + '\r\n';

  rval += '-----END ' + msg.type + '-----\r\n';
  return rval;
};

/**
 * Decodes (deserializes) all PEM messages found in the given string.
 *
 * @param str the PEM-formatted string to decode.
 *
 * @return the PEM message objects in an array.
 */
pem.decode = function(str) {
  var rval = [];

  // split string into PEM messages (be lenient w/EOF on BEGIN line)
  var messages = _pemMessageScanner(str);
  // the name must start at the beginning of a run of printable chars, which
  // gives the same match as an unanchored search without quadratic retries
  var rHeader = /(?:^|[^\x21-\x7e])([\x21-\x7e]+):\s*([\x21-\x7e\s^:]+)/;
  var rCRLF = /\r?\n/;
  var match;
  while(true) {
    match = messages.next();
    if(!match) {
      break;
    }

    // accept "NEW CERTIFICATE REQUEST" as "CERTIFICATE REQUEST"
    // https://datatracker.ietf.org/doc/html/rfc7468#section-7
    var type = match[1];
    if(type === 'NEW CERTIFICATE REQUEST') {
      type = 'CERTIFICATE REQUEST';
    }

    var msg = {
      type: type,
      procType: null,
      contentDomain: null,
      dekInfo: null,
      headers: [],
      body: forge.util.decode64(match[3])
    };
    rval.push(msg);

    // no headers
    if(!match[2]) {
      continue;
    }

    // parse headers
    var lines = match[2].split(rCRLF);
    var li = 0;
    while(match && li < lines.length) {
      // get line, trim any rhs whitespace
      var line = rtrim(lines[li]);

      // RFC2822 unfold any following folded lines
      for(var nl = li + 1; nl < lines.length; ++nl) {
        var next = lines[nl];
        if(!/\s/.test(next[0])) {
          break;
        }
        line += next;
        li = nl;
      }

      // parse header
      match = line.match(rHeader);
      if(match) {
        var header = {name: match[1], values: []};
        var values = match[2].split(',');
        for(var vi = 0; vi < values.length; ++vi) {
          header.values.push(ltrim(values[vi]));
        }

        // Proc-Type must be the first header
        if(!msg.procType) {
          if(header.name !== 'Proc-Type') {
            throw new Error('Invalid PEM formatted message. The first ' +
              'encapsulated header must be "Proc-Type".');
          } else if(header.values.length !== 2) {
            throw new Error('Invalid PEM formatted message. The "Proc-Type" ' +
              'header must have two subfields.');
          }
          msg.procType = {version: values[0], type: values[1]};
        } else if(!msg.contentDomain && header.name === 'Content-Domain') {
          // special-case Content-Domain
          msg.contentDomain = values[0] || '';
        } else if(!msg.dekInfo && header.name === 'DEK-Info') {
          // special-case DEK-Info
          if(header.values.length === 0) {
            throw new Error('Invalid PEM formatted message. The "DEK-Info" ' +
              'header must have at least one subfield.');
          }
          msg.dekInfo = {algorithm: values[0], parameters: values[1] || null};
        } else {
          msg.headers.push(header);
        }
      }

      ++li;
    }

    if(msg.procType === 'ENCRYPTED' && !msg.dekInfo) {
      throw new Error('Invalid PEM formatted message. The "DEK-Info" ' +
        'header must be present if "Proc-Type" is "ENCRYPTED".');
    }
  }

  if(rval.length === 0) {
    throw new Error('Invalid PEM formatted message.');
  }

  return rval;
};

function foldHeader(header) {
  var rval = header.name + ': ';

  // ensure values with CRLF are folded
  var values = [];
  var insertSpace = function(match, $1) {
    return ' ' + $1;
  };
  for(var i = 0; i < header.values.length; ++i) {
    values.push(header.values[i].replace(/^(\S+\r\n)/, insertSpace));
  }
  rval += values.join(',') + '\r\n';

  // do folding
  var length = 0;
  var candidate = -1;
  for(var i = 0; i < rval.length; ++i, ++length) {
    if(length > 65 && candidate !== -1) {
      var insert = rval[candidate];
      if(insert === ',') {
        ++candidate;
        rval = rval.substr(0, candidate) + '\r\n ' + rval.substr(candidate);
      } else {
        rval = rval.substr(0, candidate) +
          '\r\n' + insert + rval.substr(candidate + 1);
      }
      length = (i - candidate - 1);
      candidate = -1;
      ++i;
    } else if(rval[i] === ' ' || rval[i] === '\t' || rval[i] === ',') {
      candidate = i;
    }
  }

  return rval;
}

function ltrim(str) {
  return str.replace(/^\s+/, '');
}

// a loop, since /\s+$/ is quadratic on whitespace followed by non-whitespace
function rtrim(str) {
  var end = str.length;
  while(end > 0 && /\s/.test(str.charAt(end - 1))) {
    --end;
  }
  return str.substring(0, end);
}

/**
 * Creates a scanner for the PEM messages in a string. It finds the same
 * matches as this regular expression, except that only the shortest label
 * followed by '-----' is tried (RFC 7468 labels can't contain '--'):
 *
 * /\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7e\s]+?(?:\r?\n\r?\n))?
 *   ([:A-Za-z0-9+\/=\s]+?)-----END \1-----/g
 *
 * The regular expression takes polynomial time on input without a matching
 * END line. The scanner indexes the END lines once instead, so each BEGIN
 * line is matched without rescanning the input.
 *
 * @param str the string to scan.
 *
 * @return an object whose next() returns the next match as
 *   [match, label, headers, body] (headers may be undefined), or null.
 */
function _pemMessageScanner(str) {
  var rBody = /[:A-Za-z0-9+\/=\s]/;
  var rNotBody = /[^:A-Za-z0-9+\/=\s]/g;
  var rNotHeader = /[^\x21-\x7e\s]/g;
  var rLabel = /[A-Z0-9- ]/;

  // index of the first char at or after i matched by a global regex
  function indexOfRegex(regex, i) {
    regex.lastIndex = i;
    var match = regex.exec(str);
    return match ? match.index : str.length;
  }

  // shortest label at i followed by '-----', or null
  function labelAt(i) {
    for(var j = i; j < str.length && rLabel.test(str.charAt(j)); ++j) {
      if(j > i && str.substr(j, 5) === '-----') {
        return str.substring(i, j);
      }
    }
    return null;
  }

  // end of a blank line (\r?\n\r?\n) starting at i, or -1
  function blankLineEnd(i) {
    if(str.charAt(i) === '\r') {
      ++i;
    }
    if(str.charAt(i) !== '\n') {
      return -1;
    }
    if(str.charAt(++i) === '\r') {
      ++i;
    }
    return str.charAt(i) === '\n' ? i + 1 : -1;
  }

  // first i in [start, end) where a blank line ends before end, or -1
  function firstBlankLine(start, end) {
    for(var i = start; i < end; ++i) {
      var v = blankLineEnd(i);
      if(v !== -1 && v < end) {
        return i;
      }
    }
    return -1;
  }

  // the headers group ends at a blank line inside the run of body chars
  // before an END line; index END lines by label, with the first such
  // blank line
  var ends = {};
  for(var end = str.indexOf('-----END '); end !== -1;
    end = str.indexOf('-----END ', end + 1)) {
    var endLabel = labelAt(end + 9);
    var start = end;
    while(start > 0 && rBody.test(str.charAt(start - 1))) {
      --start;
    }
    var blank = firstBlankLine(start, end);
    if(endLabel !== null && blank !== -1) {
      var key = '$' + endLabel;
      (ends[key] = ends[key] || []).push({end: end, blank: blank});
    }
  }

  var pos = 0;
  var headerEnd = -1;
  return {
    next: function() {
      var begin;
      while((begin = str.indexOf('-----BEGIN ', pos)) !== -1) {
        pos = begin + 1;
        var label = labelAt(begin + 11);
        if(label === null) {
          continue;
        }
        var q = begin + 16 + label.length;

        // the body is the run of body chars that ends at a matching END line
        var bodyEnd = indexOfRegex(rNotBody, q);
        var bodyEndOk = str.substr(bodyEnd, 9) === '-----END ' &&
          labelAt(bodyEnd + 9) === label;
        // headers chars end here (q never decreases between BEGIN lines)
        if(q > headerEnd) {
          headerEnd = indexOfRegex(rNotHeader, q);
        }
        // first later matching END line with a blank line before it
        var later = null;
        var list = ends['$' + label];
        if(list) {
          var lo = 0;
          var hi = list.length;
          while(lo < hi) {
            var mid = (lo + hi) >> 1;
            if(list[mid].end > bodyEnd) {
              hi = mid;
            } else {
              lo = mid + 1;
            }
          }
          later = list[lo] || null;
        }

        // \r?\n? tries to consume as much as possible first
        var starts = [];
        if(str.charAt(q) === '\r') {
          if(str.charAt(q + 1) === '\n') {
            starts.push(q + 2);
          }
          starts.push(q + 1);
        } else if(str.charAt(q) === '\n') {
          starts.push(q + 1);
        }
        starts.push(q);

        for(var i = 0; i < starts.length; ++i) {
          var t = starts[i];
          // optional headers: up to the first blank line that a non-empty
          // body and the END line follow
          var blank = bodyEndOk ? firstBlankLine(t + 1, bodyEnd) : -1;
          var end = bodyEnd;
          if(blank === -1 && later) {
            blank = later.blank;
            end = later.end;
          }
          if(blank !== -1 && blank <= headerEnd) {
            var v = blankLineEnd(blank);
            pos = end + 14 + label.length;
            return [str.substring(begin, pos), label,
              str.substring(t, v), str.substring(v, end)];
          }
          // no headers
          if(bodyEndOk && t < bodyEnd) {
            pos = bodyEnd + 14 + label.length;
            return [str.substring(begin, pos), label,
              undefined, str.substring(t, bodyEnd)];
          }
        }
      }
      return null;
    }
  };
}
