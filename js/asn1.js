/**
 * Javascript implementation of Abstract Syntax Notation Number One.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 *
 * An API for storing data using the Abstract Syntax Notation Number One
 * format using DER (Distinguished Encoding Rules) encoding. This encoding is
 * commonly used to store data for PKI, i.e. X.509 Certificates, and this
 * implementation exists for that purpose.
 *
 * Abstract Syntax Notation Number One (ASN.1) is used to define the abstract
 * syntax of information without restricting the way the information is encoded
 * for transmission. It provides a standard that allows for open systems
 * communication. ASN.1 defines the syntax of information data and a number of
 * simple data types as well as a notation for describing them and specifying
 * values for them.
 *
 * The RSA algorithm creates public and private keys that are often stored in
 * X.509 or PKCS#X formats -- which use ASN.1 (encoded in DER format). This
 * class provides the most basic functionality required to store and load DSA
 * keys that are encoded according to ASN.1.
 *
 * The most common binary encodings for ASN.1 are BER (Basic Encoding Rules)
 * and DER (Distinguished Encoding Rules). DER is just a subset of BER that
 * has stricter requirements for how data must be encoded.
 *
 * Each ASN.1 structure has a tag (a byte identifying the ASN.1 structure type)
 * and a byte array for the value of this ASN1 structure which may be data or a
 * list of ASN.1 structures.
 *
 * Each ASN.1 structure using BER is (Tag-Length-Value):
 *
 * | byte 0 | bytes X | bytes Y |
 * |--------|---------|----------
 * |  tag   | length  |  value  |
 *
 * ASN.1 allows for tags to be of "High-tag-number form" which allows a tag to
 * be two or more octets, but that is not supported by this class. A tag is
 * only 1 byte. Bits 1-5 give the tag number (ie the data type within a
 * particular 'class'), 6 indicates whether or not the ASN.1 value is
 * constructed from other ASN.1 values, and bits 7 and 8 give the 'class'. If
 * bits 7 and 8 are both zero, the class is UNIVERSAL. If only bit 7 is set,
 * then the class is APPLICATION. If only bit 8 is set, then the class is
 * CONTEXT_SPECIFIC. If both bits 7 and 8 are set, then the class is PRIVATE.
 * The tag numbers for the data types for the class UNIVERSAL are listed below:
 *
 * UNIVERSAL 0 Reserved for use by the encoding rules
 * UNIVERSAL 1 Boolean type
 * UNIVERSAL 2 Integer type
 * UNIVERSAL 3 Bitstring type
 * UNIVERSAL 4 Octetstring type
 * UNIVERSAL 5 Null type
 * UNIVERSAL 6 Object identifier type
 * UNIVERSAL 7 Object descriptor type
 * UNIVERSAL 8 External type and Instance-of type
 * UNIVERSAL 9 Real type
 * UNIVERSAL 10 Enumerated type
 * UNIVERSAL 11 Embedded-pdv type
 * UNIVERSAL 12 UTF8String type
 * UNIVERSAL 13 Relative object identifier type
 * UNIVERSAL 14-15 Reserved for future editions
 * UNIVERSAL 16 Sequence and Sequence-of types
 * UNIVERSAL 17 Set and Set-of types
 * UNIVERSAL 18-22, 25-30 Character string types
 * UNIVERSAL 23-24 Time types
 *
 * The length of an ASN.1 structure is specified after the tag identifier.
 * There is a definite form and an indefinite form. The indefinite form may
 * be used if the encoding is constructed and not all immediately available.
 * The indefinite form is encoded using a length byte with only the 8th bit
 * set. The end of the constructed object is marked using end-of-contents
 * octets (two zero bytes).
 *
 * The definite form looks like this:
 *
 * The length may take up 1 or more bytes, it depends on the length of the
 * value of the ASN.1 structure. DER encoding requires that if the ASN.1
 * structure has a value that has a length greater than 127, more than 1 byte
 * will be used to store its length, otherwise just one byte will be used.
 * This is strict.
 *
 * In the case that the length of the ASN.1 value is less than 127, 1 octet
 * (byte) is used to store the "short form" length. The 8th bit has a value of
 * 0 indicating the length is "short form" and not "long form" and bits 7-1
 * give the length of the data. (The 8th bit is the left-most, most significant
 * bit: also known as big endian or network format).
 *
 * In the case that the length of the ASN.1 value is greater than 127, 2 to
 * 127 octets (bytes) are used to store the "long form" length. The first
 * byte's 8th bit is set to 1 to indicate the length is "long form." Bits 7-1
 * give the number of additional octets. All following octets are in base 256
 * with the most significant digit first (typical big-endian binary unsigned
 * integer storage). So, for instance, if the length of a value was 257, the
 * first byte would be set to:
 *
 * 10000010 = 130 = 0x82.
 *
 * This indicates there are 2 octets (base 256) for the length. The second and
 * third bytes (the octets just mentioned) would store the length in base 256:
 *
 * octet 2: 00000001 = 1 * 256^1 = 256
 * octet 3: 00000001 = 1 * 256^0 = 1
 * total = 257
 *
 * The algorithm for converting a js integer value of 257 to base-256 is:
 *
 * var value = 257;
 * var bytes = [];
 * bytes[0] = (value >>> 8) & 0xFF; // most significant byte first
 * bytes[1] = value & 0xFF;        // least significant byte last
 *
 * On the ASN.1 UNIVERSAL Object Identifier (OID) type:
 *
 * An OID can be written like: "value1.value2.value3...valueN"
 *
 * The DER encoding rules:
 *
 * The first byte has the value 40 * value1 + value2.
 * The following bytes, if any, encode the remaining values. Each value is
 * encoded in base 128, most significant digit first (big endian), with as
 * few digits as possible, and the most significant bit of each byte set
 * to 1 except the last in each value's encoding. For example: Given the
 * OID "1.2.840.113549", its DER encoding is (remember each byte except the
 * last one in each encoding is OR'd with 0x80):
 *
 * byte 1: 40 * 1 + 2 = 42 = 0x2A.
 * bytes 2-3: 128 * 6 + 72 = 840 = 6 72 = 6 72 = 0x0648 = 0x8648
 * bytes 4-6: 16384 * 6 + 128 * 119 + 13 = 6 119 13 = 0x06770D = 0x86F70D
 *
 * The final value is: 0x2A864886F70D.
 * The full OID (including ASN.1 tag and length of 6 bytes) is:
 * 0x06062A864886F70D
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

// TODO: Better abstract ASN.1 away from its serialization (DER) and support BER

/* ASN.1 API */
var asn1 = forge.asn1 = forge.asn1 || {};

/**
 * ASN.1 classes.
 */
asn1.Class = {
  UNIVERSAL:        0x00,
  APPLICATION:      0x40,
  CONTEXT_SPECIFIC: 0x80,
  PRIVATE:          0xC0
};

/**
 * ASN.1 types. Not all types are supported by this implementation, only
 * those necessary to implement a simple PKI are implemented.
 */
asn1.Type = {
  NONE:             0,
  BOOLEAN:          1,
  INTEGER:          2,
  BITSTRING:        3,
  OCTETSTRING:      4,
  NULL:             5,
  OID:              6,
  ODESC:            7,
  EXTERNAL:         8,
  REAL:             9,
  ENUMERATED:      10,
  EMBEDDED:        11,
  UTF8:            12,
  ROID:            13,
  SEQUENCE:        16,
  SET:             17,
  PRINTABLESTRING: 19,
  IA5STRING:       22,
  UTCTIME:         23,
  GENERALIZEDTIME: 24,
  BMPSTRING:       30
};

var ByteBuffer = forge.util.ByteBuffer;

/**
 * Creates a new asn1 object. The given value must be compatible with the
 * given type.
 *
 * @param tagClass the tag class for the object.
 * @param type the data type (tag number) for the object.
 * @param constructed true if the asn1 object is in constructed form.
 * @param value the value for the object as a JavaScript primitive or
 *          a ByteBuffer, if it is not constructed, otherwise an array of
 *          other asn1 objects.
 *
 * Required value types based on asn1.Types:
 *
 * OID: string (in dotted format)
 * BOOLEAN: boolean or ByteBuffer
 * INTEGER: number (if < 32 bit) or ByteBuffer
 * NULL: null
 * UTF8, PRINTABLESTRING, IA5STRING, BMPSTRING: string
 * UTCTIME, GENERALIZEDTIME: Date or string
 *
 * @return the asn1 object.
 */
asn1.create = function(tagClass, type, constructed, value) {
  /* An asn1 object has a tagClass, a type, a constructed flag, and a
    value. The value's type depends on the constructed flag. If
    constructed, it will contain a list of other asn1 objects. If not,
    it will contain the ASN.1 value in an appropriate native representation
    or as a ByteBuffer containing bytes formatted according to the ASN.1
    data type. */

  // remove undefined values
  var isArray = forge.util.isArray(value);
  if(isArray) {
    var tmp = [];
    for(var i = 0; i < value.length; ++i) {
      if(value[i] !== undefined) {
        tmp.push(value[i]);
      }
    }
    value = tmp;
  } else {
    // validate value type
    switch(type) {
    case asn1.Type.OID:
      if(typeof value !== 'string') {
        throw new TypeError('value must be a string for type OID.');
      }
      break;
    case asn1.Type.BOOLEAN:
      if(typeof value !== 'boolean' && !(value instanceof ByteBuffer)) {
        throw new TypeError(
          'value must be a boolean or a ByteBuffer for type BOOLEAN.');
      }
      break;
    case asn1.Type.INTEGER:
      if(typeof value !== 'number' && !(value instanceof ByteBuffer)) {
        throw new TypeError(
          'value must be a number or a ByteBuffer for type INTEGER.');
      }
      break;
    case asn1.Type.NULL:
      if(value !== null) {
        throw new TypeError('value must be null for type NULL.');
      }
      break;
    case asn1.Type.UTF8:
      if(typeof value !== 'string') {
        throw new TypeError('value must be a string for type UTF8.');
      }
      break;
    case asn1.Type.PRINTABLESTRING:
      if(typeof value !== 'string') {
        throw new TypeError('value must be a string for type PRINTABLESTRING.');
      }
      break;
    case asn1.Type.IA5STRING:
      if(typeof value !== 'string') {
        throw new TypeError('value must be a string for type IA5STRING.');
      }
      break;
    case asn1.Type.UTCTIME:
      if(typeof value !== 'string' && !(value instanceof Date)) {
        throw new TypeError('value must be a string or Date for type UTCTIME.');
      }
      break;
    case asn1.Type.GENERALIZEDTIME:
      if(typeof value !== 'string' && !(value instanceof Date)) {
        throw new TypeError(
          'value must be a string or Date for type GENERALIZEDTIME.');
      }
      break;
    case asn1.Type.BMPSTRING:
      if(typeof value !== 'string') {
        throw new TypeError('value must be a string for type BMPSTRING.');
      }
      break;
    default:
      if(!(value instanceof ByteBuffer)) {
        throw new TypeError('value must be a ByteBuffer.');
      }
    }
  }

  return {
    tagClass: tagClass,
    type: type,
    constructed: constructed,
    composed: constructed || isArray,
    value: value
  };
};

/**
 * Parses an asn1 object from a ByteBuffer with DER-formatted data.
 *
 * @param der the ByteBuffer to parse from.
 * @param strict true to be strict when checking value lengths, false to
 *          allow truncated values (default: true).
 *
 * @return the parsed asn1 object.
 */
asn1.fromDer = function(der, strict) {
  if(!(der instanceof ByteBuffer)) {
    throw new TypeError('der must be a ByteBuffer.');
  }

  if(strict === undefined) {
    strict = true;
  }

  // minimum length for ASN.1 DER structure is 2
  if(der.length() < 2) {
    var error = new Error('Too few bytes to parse DER.');
    error.bytes = der.length();
    throw error;
  }

  // get the first byte
  var b1 = der.getByte();

  // get the tag class
  var tagClass = (b1 & 0xC0);

  // get the type (bits 1-5)
  var type = b1 & 0x1F;

  // get the value length
  var length = _getValueLength(der);

  // ensure there are enough bytes to get the value
  if(der.length() < length) {
    if(strict) {
      var error = new Error('Too few bytes to read ASN.1 value.');
      error.detail = der.length() + ' < ' + length;
      throw error;
    }
    // Note: be lenient with truncated values
    length = der.length();
  }

  // prepare to get value
  var value;

  // constructed flag is bit 6 (32 = 0x20) of the first byte
  var constructed = ((b1 & 0x20) === 0x20);

  // determine if the value is composed of other ASN.1 objects (if its
  // constructed it will be and if its a BITSTRING it may be)
  var composed = constructed;
  if(!composed && tagClass === asn1.Class.UNIVERSAL &&
    type === asn1.Type.BITSTRING && length > 1) {
    /* The first octet gives the number of bits by which the length of the
      bit string is less than the next multiple of eight (this is called
      the "number of unused bits").

      The second and following octets give the value of the bit string
      converted to an octet string. */
    // if there are no unused bits, maybe the bitstring holds ASN.1 objs
    var read = der.read;
    var unused = der.getByte();
    if(unused === 0) {
      // if the first byte indicates UNIVERSAL or CONTEXT_SPECIFIC,
      // and the length is valid, assume we've got an ASN.1 object
      b1 = der.getByte();
      var tc = (b1 & 0xC0);
      if(tc === asn1.Class.UNIVERSAL || tc === asn1.Class.CONTEXT_SPECIFIC) {
        try {
          var len = _getValueLength(der);
          composed = (len === length - (der.read - read));
          if(composed) {
            // adjust read/length to account for unused bits byte
            ++read;
            --length;
          }
        } catch(ex) {}
      }
    }
    // restore read pointer
    der.read = read;
  }

  if(composed) {
    // parse child asn1 objects from the value
    value = [];
    if(length === undefined) {
      // asn1 object of indefinite length, read until end tag
      for(;;) {
        if(der.bytes(2) === String.fromCharCode(0, 0)) {
          der.getBytes(2);
          break;
        }
        value.push(asn1.fromDer(der, strict));
      }
    } else {
      // parsing asn1 object of definite length
      var start = der.length();
      while(length > 0) {
        value.push(asn1.fromDer(der, strict));
        length -= start - der.length();
        start = der.length();
      }
    }
  } else {
    // asn1 not composed, get raw value
    if(length === undefined) {
      if(strict) {
        throw new Error('Non-constructed ASN.1 object of indefinite length.');
      }
      // be lenient and use remaining bytes
      length = der.length();
    }

    value = new ByteBuffer();
    value.putBytes(der.getBytes(length));
    value = asn1.derToNative(value, type);
  }

  // create and return asn1 object
  return asn1.create(tagClass, type, constructed, value);
};

/**
 * Converts the given asn1 object to a ByteBuffer with DER-formatted data.
 *
 * @param asn1 the asn1 object to DER-encode.
 *
 * @return the ByteBuffer.
 */
asn1.toDer = function(obj) {
  var der = new ByteBuffer();

  // build the first byte
  var b1 = obj.tagClass | obj.type;

  // for storing the ASN.1 value
  var value = new ByteBuffer();

  // if composed, use each child asn1 object's DER bytes as value
  if(obj.composed) {
    // turn on 6th bit (0x20 = 32) to indicate asn1 is constructed
    // from other asn1 objects
    if(obj.constructed) {
      b1 |= 0x20;
    } else {
      // type is a bit string, add unused bits of 0x00
      value.putByte(0x00);
    }

    // add all of the child DER bytes together
    for(var i = 0; i < obj.value.length; ++i) {
      if(obj.value[i] !== undefined) {
        value.putBuffer(asn1.toDer(obj.value[i]));
      }
    }
  } else {
    // convert non-composed from native representation
    value.putBuffer(asn1.nativeToDer(obj.value, obj.type));
  }

  // add tag byte
  der.putByte(b1);

  // use "short form" encoding
  if(value.length() <= 127) {
    // one byte describes the length
    // bit 8 = 0 and bits 7-1 = length
    der.putByte(value.length() & 0x7F);
  } else {
    // use "long form" encoding
    // 2 to 127 bytes describe the length
    // first byte: bit 8 = 1 and bits 7-1 = # of additional bytes
    // other bytes: length in base 256, big-endian
    // FIXME: use ByteBuffer for lenBytes
    var len = value.length();
    var lenBytes = '';
    do {
      lenBytes += String.fromCharCode(len & 0xFF);
      len = len >>> 8;
    } while(len > 0);

    // set first byte to # bytes used to store the length and turn on
    // bit 8 to indicate long-form length is used
    der.putByte(lenBytes.length | 0x80);

    // concatenate length bytes in reverse since they were generated
    // little endian and we need big endian
    for(var i = lenBytes.length - 1; i >= 0; --i) {
      der.putByte(lenBytes.charCodeAt(i));
    }
  }

  // concatenate value bytes
  return der.putBuffer(value);
};

/**
 * Converts the given asn1 value to a native representation based on the
 * given type. If no conversion can be performed, the value is
 * returned as-is, namely, as a ByteBuffer.
 *
 * Conversions for asn1.Types:
 *
 * OID => string (in dotted format)
 * BOOLEAN => ByteBuffer (not converted to avoid losing non-zero value)
 * INTEGER => number or ByteBuffer if > 32 bit
 * NULL => null
 * UTF8, PRINTABLESTRING, IA5STRING, BMPSTRING => string
 * UTCTIME, GENERALIZEDTIME => string (not converted to Date to preserve format)
 *
 * @param der the ByteBuffer with DER-encoded bytes.
 * @param type the ASN.1 type to convert to a native form.
 *
 * @return the native representation or a ByteBuffer.
 */
asn1.derToNative = function(der, type) {
  switch(type) {
  case asn1.Type.OID:
    return asn1.derToOid(der);
  case asn1.Type.BOOLEAN:
    /* Don't convert to boolean because non-zero value is lost */
    break;
  case asn1.Type.INTEGER:
    try {
      return asn1.derToInteger(der);
    } catch(e) {
      return der;
    }
    break;
  case asn1.Type.NULL:
    return null;
  case asn1.Type.UTF8:
    return der.toString('utf8');
  case asn1.Type.PRINTABLESTRING:
  case asn1.Type.IA5STRING:
  /* Don't convert to Date object because format information is lost */
  case asn1.Type.UTCTIME:
  case asn1.Type.GENERALIZEDTIME:
    return der.toString('binary');
  case asn1.Type.BMPSTRING:
    var value = '';
    var bmp = der.copy();
    while(bmp.length() > 0) {
      value += String.fromCharCode(bmp.getInt16());
    }
    return value;
  }
  return der;
};

/**
 * Converts the given native representation of a value to a DER-encoded
 * ByteBuffer based on the given ASN.1 type.
 *
 * Valid conversions for asn1.Types:
 *
 * string (in dotted format) (OID)
 * boolean or ByteBuffer (BOOLEAN)
 * number or ByteBuffer (INTEGER)
 * null (NULL)
 * string (UTF8, PRINTABLESTRING, IA5STRING, BMPSTRING)
 * string or Date (UTCTIME, GENERALIZEDTIME)
 *
 * @param value the native value to convert.
 * @param type the ASN.1 type to use to convert.
 *
 * @return the ByteBuffer.
 */
asn1.nativeToDer = function(value, type) {
  switch(type) {
  case asn1.Type.OID:
    if(typeof value !== 'string') {
      throw new TypeError('value must be a string for type OID.');
    }
    return asn1.oidToDer(value);
  case asn1.Type.BOOLEAN:
    if(typeof value !== 'boolean' && !(value instanceof ByteBuffer)) {
      throw new TypeError(
        'value must be a boolean or a ByteBuffer for type BOOLEAN.');
    }
    if(value instanceof ByteBuffer) {
      return value.copy();
    } else {
      return asn1.booleanToDer(value);
    }
    break;
  case asn1.Type.INTEGER:
    if(typeof value !== 'number' && !(value instanceof ByteBuffer)) {
      throw new TypeError(
        'value must be a number or a ByteBuffer for type INTEGER.');
    }
    if(value instanceof ByteBuffer) {
      return value.copy();
    } else {
      return asn1.integerToDer(value);
    }
    break;
  case asn1.Type.NULL:
    if(value !== null) {
      throw new TypeError('value must be null for type NULL.');
    }
    // return empty buffer
    return new ByteBuffer();
  case asn1.Type.UTF8:
    if(typeof value !== 'string') {
      throw new TypeError('value must be a string for type UTF8.');
    }
    return new ByteBuffer(value, {encoding: 'utf8'});
  case asn1.Type.PRINTABLESTRING:
    if(typeof value !== 'string') {
      throw new TypeError('value must be a string for type PRINTABLESTRING.');
    }
    /* falls through */
  case asn1.Type.IA5STRING:
    if(typeof value !== 'string') {
      throw new TypeError('value must be a string for type IA5STRING.');
    }
    return new ByteBuffer(value, {encoding: 'binary'});
  case asn1.Type.UTCTIME:
    if(typeof value !== 'string' && !(value instanceof Date)) {
      throw new TypeError('value must be a string or Date for type UTCTIME.');
    }
    return asn1.utcTimeToDer(value);
  case asn1.Type.GENERALIZEDTIME:
    if(typeof value !== 'string' && !(value instanceof Date)) {
      throw new TypeError(
        'value must be a string or Date for type GENERALIZEDTIME.');
    }
    return asn1.generalizedTimeToDer(value);
  case asn1.Type.BMPSTRING:
    if(typeof value !== 'string') {
      throw new TypeError('value must be a string for type BMPSTRING.');
    }
    return asn1.bmpStringToDer(value);
  default:
    if(value instanceof ByteBuffer) {
      return value.copy();
    }
    throw new Error(
      'Could not convert native value to DER-encoded ByteBuffer; ' +
      'native type: "' + typeof value + '", ASN.1 type: "' + type + '".');
  }
};

/**
 * Converts an OID dot-separated string to a ByteBuffer. The ByteBuffer
 * contains only the DER-encoded value, not any tag or length bytes.
 *
 * @param oid the OID dot-separated string.
 *
 * @return the ByteBuffer.
 */
asn1.oidToDer = function(oid) {
  if(typeof oid !== 'string') {
    throw new TypeError('oid must be a string.');
  }

  // split OID into individual values
  var values = oid.split('.');
  var der = new ByteBuffer();

  // first byte is 40 * value1 + value2
  der.putByte(40 * parseInt(values[0], 10) + parseInt(values[1], 10));
  // other bytes are each value in base 128 with 8th bit set except for
  // the last byte for each value
  var last, valueBytes, value, b;
  for(var i = 2; i < values.length; ++i) {
    // produce value bytes in reverse because we don't know how many
    // bytes it will take to store the value
    last = true;
    valueBytes = [];
    value = parseInt(values[i], 10);
    do {
      b = value & 0x7F;
      value = value >>> 7;
      // if value is not last, then turn on 8th bit
      if(!last) {
        b |= 0x80;
      }
      valueBytes.push(b);
      last = false;
    } while(value > 0);

    // add value bytes in reverse (needs to be in big endian)
    for(var n = valueBytes.length - 1; n >= 0; --n) {
      der.putByte(valueBytes[n]);
    }
  }

  return der;
};

/**
 * Converts a DER-encoded ByteBuffer to an OID dot-separated string. The
 * ByteBuffer should contain only the DER-encoded value, not any tag or
 * length bytes.
 *
 * @param der the ByteBuffer.
 *
 * @return the OID dot-separated string.
 */
asn1.derToOid = function(der) {
  if(!(der instanceof ByteBuffer)) {
    throw new TypeError('der must be a ByteBuffer.');
  }

  var oid;
  der = der.copy();

  // first byte is 40 * value1 + value2
  var b = der.getByte();
  oid = Math.floor(b / 40) + '.' + (b % 40);

  // other bytes are each value in base 128 with 8th bit set except for
  // the last byte for each value
  var value = 0;
  while(der.length() > 0) {
    b = der.getByte();
    value = value << 7;
    // not the last byte for the value
    if(b & 0x80) {
      value += b & 0x7F;
    } else {
      // last byte
      oid += '.' + (value + b);
      value = 0;
    }
  }

  return oid;
};

/**
 * Converts a UTCTime value to a date.
 *
 * @param utc the UTCTime value (string or ByteBuffer) to convert.
 *
 * @return the date.
 */
asn1.utcTimeToDate = function(utc) {
  if(typeof utc !== 'string' && !(utc instanceof ByteBuffer)) {
    throw new TypeError('utc must be a string or ByteBuffer.');
  }

  /* The following formats can be used:

    YYMMDDhhmmZ
    YYMMDDhhmm+hh'mm'
    YYMMDDhhmm-hh'mm'
    YYMMDDhhmmssZ
    YYMMDDhhmmss+hh'mm'
    YYMMDDhhmmss-hh'mm'

    Where:

    YY is the least significant two digits of the year
    MM is the month (01 to 12)
    DD is the day (01 to 31)
    hh is the hour (00 to 23)
    mm are the minutes (00 to 59)
    ss are the seconds (00 to 59)
    Z indicates that local time is GMT, + indicates that local time is
    later than GMT, and - indicates that local time is earlier than GMT
    hh' is the absolute value of the offset from GMT in hours
    mm' is the absolute value of the offset from GMT in minutes */
  var date = new Date();
  if(utc instanceof ByteBuffer) {
    utc = utc.toString('binary');
  }

  // if YY >= 50 use 19xx, if YY < 50 use 20xx
  var year = parseInt(utc.substr(0, 2), 10);
  year = (year >= 50) ? 1900 + year : 2000 + year;
  var MM = parseInt(utc.substr(2, 2), 10) - 1; // use 0-11 for month
  var DD = parseInt(utc.substr(4, 2), 10);
  var hh = parseInt(utc.substr(6, 2), 10);
  var mm = parseInt(utc.substr(8, 2), 10);
  var ss = 0;
  var end;
  var c;

  // not just YYMMDDhhmmZ
  if(utc.length > 11) {
    // get character after minutes
    c = utc.charAt(10);
    end = 10;

    // see if seconds are present
    if(c !== '+' && c !== '-') {
      // get seconds
      ss = parseInt(utc.substr(10, 2), 10);
      end += 2;
    }
  }

  // update date
  date.setUTCFullYear(year, MM, DD);
  date.setUTCHours(hh, mm, ss, 0);

  if(end) {
    // get +/- after end of time
    c = utc.charAt(end);
    if(c === '+' || c === '-') {
      // get hours+minutes offset
      var hhoffset = parseInt(utc.substr(end + 1, 2), 10);
      var mmoffset = parseInt(utc.substr(end + 4, 2), 10);

      // calculate offset in milliseconds
      var offset = hhoffset * 60 + mmoffset;
      offset *= 60000;

      // apply offset
      if(c === '+') {
        date.setTime(+date - offset);
      } else {
        date.setTime(+date + offset);
      }
    }
  }

  return date;
};

/**
 * Converts a GeneralizedTime value to a date.
 *
 * @param gentime the GeneralizedTime value (string or ByteBuffer) to convert.
 *
 * @return the date.
 */
asn1.generalizedTimeToDate = function(gentime) {
  if(typeof gentime !== 'string' && !(gentime instanceof ByteBuffer)) {
    throw new TypeError('generalized time must be a string or ByteBuffer.');
  }

  /* The following formats can be used:

    YYYYMMDDHHMMSS
    YYYYMMDDHHMMSS.fff
    YYYYMMDDHHMMSSZ
    YYYYMMDDHHMMSS.fffZ
    YYYYMMDDHHMMSS+hh'mm'
    YYYYMMDDHHMMSS.fff+hh'mm'
    YYYYMMDDHHMMSS-hh'mm'
    YYYYMMDDHHMMSS.fff-hh'mm'

    Where:

    YYYY is the year
    MM is the month (01 to 12)
    DD is the day (01 to 31)
    hh is the hour (00 to 23)
    mm are the minutes (00 to 59)
    ss are the seconds (00 to 59)
    .fff is the second fraction, accurate to three decimal places
    Z indicates that local time is GMT, + indicates that local time is
    later than GMT, and - indicates that local time is earlier than GMT
    hh' is the absolute value of the offset from GMT in hours
    mm' is the absolute value of the offset from GMT in minutes */
  var date = new Date();
  if(gentime instanceof ByteBuffer) {
    gentime = gentime.toString('binary');
  }

  var YYYY = parseInt(gentime.substr(0, 4), 10);
  var MM = parseInt(gentime.substr(4, 2), 10) - 1; // use 0-11 for month
  var DD = parseInt(gentime.substr(6, 2), 10);
  var hh = parseInt(gentime.substr(8, 2), 10);
  var mm = parseInt(gentime.substr(10, 2), 10);
  var ss = parseInt(gentime.substr(12, 2), 10);
  var fff = 0;
  var offset = 0;
  var isUTC = false;

  if(gentime.charAt(gentime.length - 1) === 'Z') {
    isUTC = true;
  }

  var end = gentime.length - 5;
  var c = gentime.charAt(end);
  if(c === '+' || c === '-') {
    // get hours+minutes offset
    var hhoffset = parseInt(gentime.substr(end + 1, 2), 10);
    var mmoffset = parseInt(gentime.substr(end + 4, 2), 10);

    // calculate offset in milliseconds
    offset = hhoffset * 60 + mmoffset;
    offset *= 60000;

    // apply offset
    if(c === '+') {
      offset *= -1;
    }

    isUTC = true;
  }

  // check for second fraction
  if(gentime.charAt(14) === '.') {
    fff = parseFloat(gentime.substr(14), 10) * 1000;
  }

  if(isUTC) {
    date.setUTCFullYear(YYYY, MM, DD);
    date.setUTCHours(hh, mm, ss, fff);

    // apply offset
    date.setTime(+date + offset);
  } else {
    date.setFullYear(YYYY, MM, DD);
    date.setHours(hh, mm, ss, fff);
  }

  return date;
};

/**
 * Converts a date to a UTCTime value.
 *
 * @param date the date to convert.
 *
 * @return the UTCTime value as a string.
 */
asn1.dateToUtcTime = function(date) {
  // FIXME: assumes proper format
  if(typeof date === 'string') {
    return date;
  }

  var rval = '';

  // create format YYMMDDhhmmssZ
  var format = [];
  format.push(('' + date.getUTCFullYear()).substr(2));
  format.push('' + (date.getUTCMonth() + 1));
  format.push('' + date.getUTCDate());
  format.push('' + date.getUTCHours());
  format.push('' + date.getUTCMinutes());
  format.push('' + date.getUTCSeconds());

  // ensure 2 digits are used for each format entry
  for(var i = 0; i < format.length; ++i) {
    if(format[i].length < 2) {
      rval += '0';
    }
    rval += format[i];
  }
  rval += 'Z';

  return rval;
};

/**
 * Converts a date to a GeneralizedTime value.
 *
 * @param date the date to convert.
 *
 * @return the GeneralizedTime value as a string.
 */
asn1.dateToGeneralizedTime = function(date) {
  // FIXME: assumes proper format
  if(typeof date === 'string') {
    return date;
  }

  var rval = '';

  // create format YYYYMMDDHHMMSSZ
  var format = [];
  format.push(('' + date.getUTCFullYear()).substr(2));
  format.push('' + (date.getUTCMonth() + 1));
  format.push('' + date.getUTCDate());
  format.push('' + date.getUTCHours());
  format.push('' + date.getUTCMinutes());
  format.push('' + date.getUTCSeconds());

  // ensure 2 digits are used for each format entry
  for(var i = 0; i < format.length; ++i) {
    if(format[i].length < 2) {
      rval += '0';
    }
    rval += format[i];
  }
  rval += 'Z';

  return rval;
};

/**
 * Converts a date to a DER-encoded UTCTime value.
 *
 * @param date the date to convert.
 *
 * @return the UTCTime value as a ByteBuffer.
 */
asn1.utcTimeToDer = function(date) {
  return new ByteBuffer(asn1.dateToUtcTime(date), {encoding: 'binary'});
};

/**
 * Converts a date to a DER-encoded GeneralizedTime value.
 *
 * @param date the date to convert.
 *
 * @return the GeneralizedTime value as a ByteBuffer.
 */
asn1.generalizedTimeToDer = function(date) {
  return new ByteBuffer(asn1.dateToGeneralizedTime(date), {encoding: 'binary'});
};

/**
 * Converts a JavaScript boolean to a DER-encoded ByteBuffer to be used
 * as the value for an BOOLEAN type.
 *
 * @param x the boolean.
 *
 * @return the ByteBuffer.
 */
asn1.booleanToDer = function(x) {
  // assume already in DER format
  if(x instanceof ByteBuffer) {
    return x.copy();
  }

  var rval = new ByteBuffer();
  if(x) {
    rval.putByte(0xFF);
  } else {
    rval.putByte(0x00);
  }
  return rval;
};

/**
 * Converts a DER-encoded ByteBuffer to a JavaScript boolean. This is
 * typically used to decode the value of an BOOLEAN type.
 *
 * @param der the ByteBuffer.
 *
 * @return the boolean.
 */
asn1.derToBoolean = function(der) {
  if(!(der instanceof ByteBuffer)) {
    throw new TypeError('der must be a ByteBuffer.');
  }
  return der.at(0) !== 0x00;
};

/**
 * Converts a JavaScript integer to a DER-encoded ByteBuffer to be used
 * as the value for an INTEGER type.
 *
 * @param x the integer.
 *
 * @return the ByteBuffer.
 */
asn1.integerToDer = function(x) {
  // assume already in DER format
  if(x instanceof ByteBuffer) {
    return x.copy();
  }

  var rval = new ByteBuffer();
  if(x >= -0x80 && x < 0x80) {
    return rval.putSignedInt(x, 8);
  }
  if(x >= -0x8000 && x < 0x8000) {
    return rval.putSignedInt(x, 16);
  }
  if(x >= -0x800000 && x < 0x800000) {
    return rval.putSignedInt(x, 24);
  }
  if(x >= -0x80000000 && x < 0x80000000) {
    return rval.putSignedInt(x, 32);
  }
  var error = new Error('Integer too large; max is 32-bits.');
  error.integer = x;
  throw error;
};

/**
 * Converts a DER-encoded ByteBuffer to a JavaScript integer. This is
 * typically used to decode the value of an INTEGER type.
 *
 * @param der the ByteBuffer.
 *
 * @return the integer.
 */
asn1.derToInteger = function(der) {
  if(!(der instanceof ByteBuffer)) {
    throw new TypeError('der must be a ByteBuffer.');
  }

  der = der.copy();
  var n = der.length() * 8;
  if(n > 32) {
    throw new Error('Integer too large; max is 32-bits.');
  }
  return der.getSignedInt(n);
};

/**
 * Converts a BMPSTRING string to a ByteBuffer.
 *
 * @param value the BMPSTRING string.
 *
 * @return the ByteBuffer.
 */
asn1.bmpStringToDer = function(value) {
  if(typeof value !== 'string') {
    throw new TypeError('value must be a string.');
  }
  var rval = new ByteBuffer();
  for(var i = 0; i < value.length; ++i) {
    rval.putInt16(value.charCodeAt(i));
  }
  return rval;
};

/**
 * Converts a DER-encoded ByteBuffer to a BMPSTRING string. The
 * ByteBuffer should contain only the DER-encoded value, not any tag or
 * length bytes.
 *
 * @param der the ByteBuffer.
 *
 * @return the BMPSTRING string.
 */
asn1.derToBmpString = function(der) {
  if(!(der instanceof ByteBuffer)) {
    throw new TypeError('der must be a ByteBuffer.');
  }
  var value = '';
  der = der.copy();
  while(der.length() > 0) {
    value += String.fromCharCode(der.getInt16());
  }
  return value;
};

/**
 * Validates the that given ASN.1 object is at least a super set of the
 * given ASN.1 structure. Only tag classes and types are checked. An
 * optional map may also be provided to capture ASN.1 values while the
 * structure is checked.
 *
 * To capture an ASN.1 value, set an object in the validator's capture
 * parameter to the key to use in the capture map. For example:
 *
 * {capture: 'foo'} will cause captureMap.foo to reference the ASN.1 value.
 *
 * To capture an auto-formatted ASN.1 value, set an object in the validator's
 * 'capture' to an object with the key 'name' referring to the name to use
 * in the capture map and the key 'format' referring to the type of format
 * to use. Valid formats are:
 *
 * asn1, boolean, number, hex, buffer, date
 *
 * Unknown formats will be ignored.
 *
 * The format 'asn1' will cause the full ASN.1 object to be captured. For
 * example:
 *
 * {capture: {name: 'foo', format: 'asn1'}} will cause captureMap.foo to
 *   be the full ASN.1 object.
 *
 * If the ASN.1 type is BOOLEAN the format 'boolean' will cause
 * a BOOLEAN value to be represented with a native boolean.
 *
 * If the ASN.1 type is INTEGER, the format 'number' will cause
 * an INTEGER value to be represented with a native number unless it is
 * greater than 32 bits in which case the validator will fail. The format
 * 'hex' will cause INTEGERs to be captured in hex. The format 'buffer' will
 * cause the INTEGER value to remain as a DER-encoded buffer.
 *
 * If the ASN.1 type is BITSTRING, the value may be auto-interpreted as a
 * composed ASN.1 structure. To avoid this in the captured value, a format
 * of 'buffer' maybe specified. This will ensure that a ByteBuffer containing
 * the BITSTRING is captured instead of an assumed ASN.1 value.
 *
 * If the ASN.1 type is a UTCTIME or GENERALIZEDTIME, then a format of 'date'
 * will cause the captured value to be a Date object.
 *
 * ASN.1 values that are ByteBuffers will be copied to allow their contents
 * to be manipulated without affecting the original ASN.1 object. This copy
 * can be avoided by capturing the entire ASN.1 object via format: 'asn1'.
 *
 * Objects in the validator may set a field 'optional' to true to indicate that
 * it isn't necessary to pass validation.
 *
 * @param obj the ASN.1 object to validate.
 * @param v the ASN.1 structure validator.
 * @param capture an optional map to capture values in.
 * @param errors an optional array for storing validation errors.
 *
 * @return true on success, false on failure.
 */
asn1.validate = function(obj, v, capture, errors) {
  var rval = false;

  // ensure tag class and type are the same if specified
  if((obj.tagClass === v.tagClass || typeof(v.tagClass) === 'undefined') &&
    (obj.type === v.type || typeof(v.type) === 'undefined')) {
    // ensure constructed flag is the same if specified
    if(obj.constructed === v.constructed ||
      typeof(v.constructed) === 'undefined') {
      rval = true;

      // handle sub values
      if(v.value && forge.util.isArray(v.value)) {
        var j = 0;
        for(var i = 0; rval && i < v.value.length; ++i) {
          rval = v.value[i].optional || false;
          if(obj.value[j]) {
            rval = asn1.validate(obj.value[j], v.value[i], capture, errors);
            if(rval) {
              ++j;
            } else if(v.value[i].optional) {
              rval = true;
            }
          }
          if(!rval && errors) {
            errors.push(
              '[' + v.name + '] ' +
              'Tag class "' + v.tagClass + '", type "' +
              v.type + '" expected value length "' +
              v.value.length + '", got "' +
              obj.value.length + '"');
          }
        }
      }

      if(rval && capture) {
        if(v.capture) {
          var captures = (forge.util.isArray(v.capture) ?
            v.capture : [v.capture]);
          for(var i = 0; i < captures.length; ++i) {
            var params = captures[i];
            var name;
            var value;
            if(typeof params !== 'object') {
              name = params;
            } else {
              // {capture: {name: 'foo', format: 'asn1|number|...'}}
              name = params.name;

              if(params.format === 'asn1') {
                value = obj;
              } else if(v.type === asn1.Type.BOOLEAN) {
                value = obj.value;
                if(params.format === 'boolean') {
                  value = asn1.derToBoolean(value);
                }
              } else if(v.type === asn1.Type.INTEGER) {
                // handle INTEGER formats
                value = obj.value;
                if(params.format === 'hex') {
                  if(!(value instanceof ByteBuffer)) {
                    value = asn1.integerToDer(value);
                  }
                  value = value.toString('hex');
                } else if(params.format === 'number' &&
                  typeof value !== 'number') {
                  errors.push(
                    '[' + v.name + '] ' +
                    'INTEGER too large to convert to native number.');
                } else if(params.format === 'buffer' &&
                  !(value instanceof ByteBuffer)) {
                  value = asn1.integerToDer(value);
                }
              } else if(v.type === asn1.Type.BITSTRING) {
                // handle BITSTRING formats
                if(!v.composed) {
                  value = obj.value;
                } else {
                  value = new ByteBuffer().putByte(0);
                  for(var i = 0; i < obj.value.length; ++i) {
                    value.putBuffer(asn1.toDer(value[i]));
                  }
                }
              } else if(v.type === asn1.Type.UTCTIME) {
                value = asn1.utcTimeToDate(obj.value);
              } else if(v.type === asn1.Type.GENERALIZEDTIME) {
                value = asn1.utcTimeToDate(obj.value);
              }
            }
            if(value === undefined) {
              if(obj.value instanceof ByteBuffer) {
                value = obj.value.copy();
              } else {
                value = obj.value;
              }
            }
            capture[name] = value;
          }
        }
      }
    } else if(errors) {
      errors.push(
        '[' + v.name + '] ' +
        'Expected constructed "' + v.constructed + '", got "' +
        obj.constructed + '"');
    }
  } else if(errors) {
    if(obj.tagClass !== v.tagClass) {
      errors.push(
        '[' + v.name + '] ' +
        'Expected tag class "' + v.tagClass + '", got "' +
        obj.tagClass + '"');
    }
    if(obj.type !== v.type) {
      errors.push(
        '[' + v.name + '] ' +
        'Expected type "' + v.type + '", got "' + obj.type + '"');
    }
  }
  return rval;
};

// regex for testing for non-latin characters
var _nonLatinRegex = /[^\\u0000-\\u00ff]/;

/**
 * Pretty prints an ASN.1 object to a string.
 *
 * @param obj the object to write out.
 * @param level the level in the tree.
 * @param indentation the indentation to use.
 *
 * @return the string.
 */
asn1.prettyPrint = function(obj, level, indentation) {
  var rval = '';

  // set default level and indentation
  level = level || 0;
  indentation = indentation || 2;

  // start new line for deep levels
  if(level > 0) {
    rval += '\n';
  }

  // create indent
  var indent = '';
  for(var i = 0; i < level * indentation; ++i) {
    indent += ' ';
  }

  // print class:type
  rval += indent + 'Tag: ';
  switch(obj.tagClass) {
  case asn1.Class.UNIVERSAL:
    rval += 'Universal:';
    break;
  case asn1.Class.APPLICATION:
    rval += 'Application:';
    break;
  case asn1.Class.CONTEXT_SPECIFIC:
    rval += 'Context-Specific:';
    break;
  case asn1.Class.PRIVATE:
    rval += 'Private:';
    break;
  }

  rval += obj.type;
  if(obj.tagClass === asn1.Class.UNIVERSAL) {
    // known types
    rval += ' (' + asn1.getTypeName(obj.type) + ')';
  }

  rval += '\n';
  rval += indent + 'Constructed: ' + obj.constructed + '\n';

  if(obj.composed) {
    var subvalues = 0;
    var sub = '';
    for(var i = 0; i < obj.value.length; ++i) {
      if(obj.value[i] !== undefined) {
        subvalues += 1;
        sub += asn1.prettyPrint(obj.value[i], level + 1, indentation);
        if((i + 1) < obj.value.length) {
          sub += ',';
        }
      }
    }
    rval += indent + 'Sub values: ' + subvalues + sub;
  } else {
    rval += indent + 'Value: ';
    if(obj.type === asn1.Type.OID) {
      if(forge.pki && forge.pki.oids && obj.value in forge.pki.oids) {
        rval += '(' + forge.pki.oids[obj.value] + ') ';
      }
      rval += obj.value;
    } else if(obj.type === asn1.Type.BOOLEAN) {
      if(typeof obj.value === 'boolean') {
        rval += '(' + obj.value + ') ';
        rval += '0x' + asn1.booleanToDer(obj.value).toString('hex');
      } else {
        rval += '(' + asn1.derToBoolean(obj.value) + ') ';
        rval += '0x' + obj.value.toString('hex');
      }
    } else if(obj.type === asn1.Type.INTEGER) {
      if(typeof obj.value === 'number') {
        rval += obj.value;
      } else {
        rval += '0x' + obj.value.toString('hex');
      }
    } else if(obj.type === asn1.Type.NULL) {
      rval += '[null]';
    } else if(obj.value instanceof ByteBuffer) {
      if(obj.value.length() === 0) {
        rval += '[null]';
      } else {
        var binary = obj.value.toString('binary');
        if(!_nonLatinRegex.test(binary)) {
          rval += '(' + binary + ') ';
        }
        rval += '0x' + obj.value.toString('hex');
      }
    } else {
      rval += obj.value;
    }
  }

  return rval;
};

asn1.getTypeName = function(type) {
  // known types
  switch(type) {
  case asn1.Type.NONE:
    return 'None';
  case asn1.Type.BOOLEAN:
    return 'Boolean';
  case asn1.Type.BITSTRING:
    return 'Bit String';
  case asn1.Type.INTEGER:
    return 'Integer';
  case asn1.Type.OCTETSTRING:
    return 'Octet String';
  case asn1.Type.NULL:
    return 'Null';
  case asn1.Type.OID:
    return 'Object Identifier';
  case asn1.Type.ODESC:
    return 'Object Descriptor';
  case asn1.Type.EXTERNAL:
    return 'External or Instance of';
  case asn1.Type.REAL:
    return 'Real';
  case asn1.Type.ENUMERATED:
    return 'Enumerated';
  case asn1.Type.EMBEDDED:
    return 'Embedded PDV';
  case asn1.Type.UTF8:
    return 'UTF8';
  case asn1.Type.ROID:
    return 'Relative Object Identifier';
  case asn1.Type.SEQUENCE:
    return 'Sequence';
  case asn1.Type.SET:
    return 'Set';
  case asn1.Type.PRINTABLESTRING:
    return 'Printable String';
  case asn1.Type.IA5STRING:
    return 'IA5 String';
  case asn1.Type.UTCTIME:
    return 'UTC Time';
  case asn1.Type.GENERALIZEDTIME:
    return 'Generalized Time';
  case asn1.Type.BMPSTRING:
    return 'BMP String';
  default:
    return '' + type;
  }
};

/**
 * Gets the length of an ASN.1 value.
 *
 * In case the length is not specified, undefined is returned.
 *
 * @param b the ASN.1 ByteBuffer.
 *
 * @return the length of the ASN.1 value.
 */
function _getValueLength(b) {
  var b2 = b.getByte();
  if(b2 === 0x80) {
    return undefined;
  }

  // see if the length is "short form" or "long form" (bit 8 set)
  var length;
  var longForm = b2 & 0x80;
  if(!longForm) {
    // length is just the first byte
    length = b2;
  } else {
    // the number of bytes the length is specified in bits 7 through 1
    // and each length byte is in big-endian base-256
    length = b.getInt((b2 & 0x7F) << 3);
  }
  return length;
}

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'asn1';
if(typeof define !== 'function') {
  // NodeJS -> AMD
  if(typeof module === 'object' && module.exports) {
    var nodeJS = true;
    define = function(ids, factory) {
      factory(require, module);
    };
  } else {
    // <script>
    if(typeof forge === 'undefined') {
      forge = {};
    }
    return initModule(forge);
  }
}
// AMD
var deps;
var defineFunc = function(require, module) {
  module.exports = function(forge) {
    var mods = deps.map(function(dep) {
      return require(dep);
    }).concat(initModule);
    // handle circular dependencies
    forge = forge || {};
    forge.defined = forge.defined || {};
    if(forge.defined[name]) {
      return forge[name];
    }
    forge.defined[name] = true;
    for(var i = 0; i < mods.length; ++i) {
      mods[i](forge);
    }
    return forge[name];
  };
};
var tmpDefine = define;
define = function(ids, factory) {
  deps = (typeof ids === 'string') ? factory.slice(2) : ids.slice(2);
  if(nodeJS) {
    delete define;
    return tmpDefine.apply(null, Array.prototype.slice.call(arguments, 0));
  }
  define = tmpDefine;
  return define.apply(null, Array.prototype.slice.call(arguments, 0));
};
define(['require', 'module', './util', './oids'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
