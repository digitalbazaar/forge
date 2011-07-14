/**
 * Javascript implementation of JSON-LD.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2011 Digital Bazaar, Inc. All rights reserved.
 */
(function()
{

// define forge
if(typeof(window) !== 'undefined')
{
   var forge = window.forge = window.forge || {};
   forge.jsonld = {};
}
// define node.js module
else if(typeof(module) !== 'undefined' && module.exports)
{
   var forge = {};
   module.exports = forge.jsonld = {};
}

// local defines for keywords
var __s = '@subject';
var __t = '@type';

/*
 * JSON-LD API.
 */ 
var jsonld = forge.jsonld;
jsonld.ns =
{
   rdf: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
   xsd: 'http://www.w3.org/2001/XMLSchema#'
};

var xsd =
{
   anyType: jsonld.ns.xsd + 'anyType',
   boolean: jsonld.ns.xsd + 'boolean',
   double: jsonld.ns.xsd + 'double',
   integer: jsonld.ns.xsd + 'integer',
   anyURI: jsonld.ns.xsd + 'anyURI'
};

/**
 * Creates the JSON-LD default context.
 *
 * @return the JSON-LD default context.
 */
var _createDefaultContext = function()
{
   var ctx =
   {
      rdf: jsonld.ns.rdf,
      rdfs: 'http://www.w3.org/2000/01/rdf-schema#',
      owl: 'http://www.w3.org/2002/07/owl#',
      xsd: 'http://www.w3.org/2001/XMLSchema#',
      dcterms: 'http://purl.org/dc/terms/',
      foaf: 'http://xmlns.com/foaf/0.1/',
      cal: 'http://www.w3.org/2002/12/cal/ical#',
      vcard: 'http://www.w3.org/2006/vcard/ns#',
      geo: 'http://www.w3.org/2003/01/geo/wgs84_pos#',
      cc: 'http://creativecommons.org/ns#',
      sioc: 'http://rdfs.org/sioc/ns#',
      doap: 'http://usefulinc.com/ns/doap#',
      com: 'http://purl.org/commerce#',
      ps: 'http://purl.org/payswarm#',
      gr: 'http://purl.org/goodrelations/v1#',
      sig: 'http://purl.org/signature#',
      ccard: 'http://purl.org/commerce/creditcard#',
      '@coerce':
      {
         'xsd:anyURI': ['foaf:homepage', 'foaf:member'],
         'xsd:integer': 'foaf:age'
      },
      '@vocab': ''
   };
   return ctx;
};

/**
 * Compacts an IRI into a term or CURIE if it can be. IRIs will not be
 * compacted to relative IRIs if they match the given context's default
 * vocabulary.
 *
 * @param ctx the context to use.
 * @param iri the IRI to compact.
 * @param usedCtx a context to update if a value was used from "ctx".
 *
 * @return the compacted IRI as a term or CURIE or the original IRI.
 */
var _compactIri = function(ctx, iri, usedCtx)
{
   var rval = null;
   
   // check the context for a term that could shorten the IRI
   // (give preference to terms over CURIEs)
   for(var key in ctx)
   {
      // skip special context keys (start with '@')
      if(key.length > 0 && key[0] !== '@')
      {
         // compact to a term
         if(iri === ctx[key])
         {
            rval = key;
            if(usedCtx !== null)
            {
               usedCtx[key] = ctx[key];
            }
            break;
         }
      }
   }
   
   // term not found, if term is rdf type, use built-in keyword
   if(rval === null && iri === jsonld.ns.rdf + 'type')
   {
      rval = __t;
   }
   
   // term not found, check the context for a CURIE prefix
   if(rval === null)
   {
      for(var key in ctx)
      {
         // skip special context keys (start with '@')
         if(key.length > 0 && key[0] !== '@')
         {
            // see if IRI begins with the next IRI from the context
            var ctxIri = ctx[key];
            var idx = iri.indexOf(ctxIri);
            
            // compact to a CURIE
            if(idx === 0 && iri.length > ctxIri.length)
            {
               rval = key + ':' + iri.substr(ctxIri.length);
               if(usedCtx !== null)
               {
                  usedCtx[key] = ctxIri;
               }
               break;
            }
         }
      }
   }

   // could not compact IRI
   if(rval === null)
   {
      rval = iri;
   }

   return rval;
};

/**
 * Expands a term into an absolute IRI. The term may be a regular term, a
 * CURIE, a relative IRI, or an absolute IRI. In any case, the associated
 * absolute IRI will be returned.
 *
 * @param ctx the context to use.
 * @param term the term to expand.
 * @param usedCtx a context to update if a value was used from "ctx".
 *
 * @return the expanded term as an absolute IRI.
 */
var _expandTerm = function(ctx, term, usedCtx)
{
   var rval;
   
   // 1. If the property has a colon, then it is a CURIE or an absolute IRI:
   var idx = term.indexOf(':');
   if(idx != -1)
   {
      // get the potential CURIE prefix
      var prefix = term.substr(0, idx);

      // 1.1. See if the prefix is in the context:
      if(prefix in ctx)
      {
         // prefix found, expand property to absolute IRI
         rval = ctx[prefix] + term.substr(idx + 1);
         if(usedCtx !== null)
         {
            usedCtx[prefix] = ctx[prefix];
         }
      }
      // 1.2. Prefix is not in context, property is already an absolute IRI:
      else
      {
         rval = term;
      }
   }
   // 2. If the property is in the context, then it's a term.
   else if(term in ctx)
   {
      rval = ctx[term];
      if(usedCtx !== null)
      {
         usedCtx[term] = rval;
      }
   }
   // 3. The property is the special-case subject.
   else if(term === __s)
   {
      rval = __s;
   }
   // 4. The property is the special-case rdf type.
   else if(term === __t)
   {
      rval = jsonld.ns.rdf + 'type';
   }
   // 5. The property is a relative IRI, prepend the default vocab.
   else
   {
      rval = ctx['@vocab'] + term;
      if(usedCtx !== null)
      {
         usedCtx['@vocab'] = ctx['@vocab'];
      }
   }

   return rval;
};

/**
 * Sets a subject's property to the given object value. If a value already
 * exists, it will be appended to an array.
 *
 * @param s the subject.
 * @param p the property.
 * @param o the object.
 */
var _setProperty = function(s, p, o)
{
   if(p in s)
   {
      if(s[p].constructor === Array)
      {
         s[p].push(o);
      }
      else
      {
         s[p] = [s[p], o];
      }
   }
   else
   {
      s[p] = o;
   }
};

/**
 * Clones a string/number or an object and sorts the keys. Deep clone
 * is not performed. This function will deep copy arrays, but that feature
 * isn't needed in this implementation at present. If it is needed in the
 * future, it will have to be implemented here.
 * 
 * @param value the value to clone.
 * 
 * @return the cloned value.
 */
var _clone = function(value)
{
   var rval;
   
   if(value.constructor === Object)
   {
      rval = {};
      var keys = Object.keys(value).sort();
      for(var i in keys)
      {
         var key = keys[i];
         if(value[key].constructor === Array)
         {
            rval[key] = value[key].slice();
         }
         else
         {
            rval[key] = value[key];
         }
      }
   }
   else
   {
      rval = value;
   }
   
   return rval;
};

/**
 * Clones a context.
 * 
 * @param ctx the context to clone.
 * 
 * @return the clone of the context.
 */
var _cloneContext = function(ctx)
{
   var rval = {};
   for(var key in ctx)
   {
      // deep-copy @coerce
      if(key === '@coerce')
      {
         rval['@coerce'] = {};
         for(var type in ctx['@coerce'])
         {
            var p = ctx['@coerce'][type];
            rval['@coerce'][type] = (p.constructor === Array) ? p.slice() : p;
         }
      }
      else
      {
         rval[key] = ctx[key];
      }
   }
   return rval;
};

/**
 * Gets the coerce type for the given property.
 *
 * @param ctx the context to use.
 * @param property the property to get the coerced type for.
 * @param usedCtx a context to update if a value was used from "ctx".
 *
 * @return the coerce type, null for none.
 */
var _getCoerceType = function(ctx, property, usedCtx)
{
   var rval = null;

   // get expanded property
   var p = _expandTerm(ctx, property, null);

   // built-in type coercion JSON-LD-isms
   if(p === __s || p === jsonld.ns.rdf + 'type')
   {
      rval = xsd.anyURI;
   }
   // check type coercion for property
   else
   {
      // force compacted property
      p = _compactIri(ctx, p, null);
      
      for(var type in ctx['@coerce'])
      {
         // get coerced properties (normalize to an array)
         var props = ctx['@coerce'][type];
         if(props.constructor !== Array)
         {
            props = [props];
         }
         
         // look for the property in the array
         for(var i in props)
         {
            // property found
            if(props[i] === p)
            {
               rval = _expandTerm(ctx, type, usedCtx);
               if(usedCtx !== null)
               {
                  if(!('@coerce' in usedCtx))
                  {
                     usedCtx['@coerce'] = {};
                  }
                  
                  if(!(type in usedCtx['@coerce']))
                  {
                     usedCtx['@coerce'][type] = p;
                  }
                  else
                  {
                     var c = usedCtx['@coerce'][type];
                     if((c.constructor === Array && c.indexOf(p) == -1) ||
                        (c.constructor === String && c !== p))
                     {
                        _setProperty(usedCtx['@coerce'], type, p);
                     }
                  }
               }
               break;
            }
         }
      }
   }

   return rval;
};

/**
 * Recursively compacts a value. This method will compact IRIs to CURIEs or
 * terms and do reverse type coercion to compact a value.
 *
 * @param ctx the context to use.
 * @param property the property that points to the value, NULL for none.
 * @param value the value to compact.
 * @param usedCtx a context to update if a value was used from "ctx".
 *
 * @return the compacted value.
 */
var _compact = function(ctx, property, value, usedCtx)
{
   var rval;
   
   if(value === null)
   {
      rval = null;
   }
   else if(value.constructor === Array)
   {
      // recursively add compacted values to array
      rval = [];
      for(var i in value)
      {
         rval.push(_compact(ctx, property, value[i], usedCtx));
      }
   }
   // graph literal/disjoint graph
   else if(
      value.constructor === Object &&
      __s in value && value[__s].constructor === Array)
   {
      rval = {};
      rval[__s] = _compact(ctx, property, value[__s], usedCtx);
   }
   // value has sub-properties if it doesn't define a literal or IRI value
   else if(
      value.constructor === Object &&
      !('@literal' in value) && !('@iri' in value))
   {
      // recursively handle sub-properties that aren't a sub-context
      rval = {};
      for(var key in value)
      {
         if(value[key] !== '@context')
         {
            // set object to compacted property
            _setProperty(
               rval, _compactIri(ctx, key, usedCtx),
               _compact(ctx, key, value[key], usedCtx));
         }
      }
   }
   else
   {
      // get coerce type
      var coerce = _getCoerceType(ctx, property, usedCtx);

      // get type from value, to ensure coercion is valid
      var type = null;
      if(value.constructor === Object)
      {
         // type coercion can only occur if language is not specified
         if(!('@language' in value))
         {
            // datatype must match coerce type if specified
            if('@datatype' in value)
            {
               type = value['@datatype'];
            }
            // datatype is IRI
            else if('@iri' in value)
            {
               type = xsd.anyURI;
            }
            // can be coerced to any type
            else
            {
               type = coerce;
            }
         }
      }
      // type can be coerced to anything
      else if(value.constructor === String)
      {
         type = coerce;
      }

      // types that can be auto-coerced from a JSON-builtin
      if(coerce === null &&
         (type === xsd.boolean || type === xsd.integer || type === xsd.double))
      {
         coerce = type;
      }

      // do reverse type-coercion
      if(coerce !== null)
      {
         // type is only null if a language was specified, which is an error
         // if type coercion is specified
         if(type === null)
         {
            throw {
               message: 'Cannot coerce type when a language is specified. ' +
                  'The language information would be lost.'
            };
         }
         // if the value type does not match the coerce type, it is an error
         else if(type !== coerce)
         {
            throw {
               message: 'Cannot coerce type because the datatype does ' +
                  'not match.'
            };
         }
         // do reverse type-coercion
         else
         {
            if(value.constructor === Object)
            {
               if('@iri' in value)
               {
                  rval = value['@iri'];
               }
               else if('@literal' in value)
               {
                  rval = value['@literal'];
               }
            }
            else
            {
               rval = value;
            }

            // do basic JSON types conversion
            if(coerce === xsd.boolean)
            {
               rval = (rval === 'true' || rval != 0);
            }
            else if(coerce === xsd.double)
            {
               rval = parseFloat(rval);
            }
            else if(coerce === xsd.integer)
            {
               rval = parseInt(rval);
            }
         }
      }
      // no type-coercion, just copy value
      else
      {
         rval = _clone(value);
      }

      // compact IRI
      if(type === xsd.anyURI)
      {
         if(rval.constructor === Object)
         {
            rval['@iri'] = _compactIri(ctx, rval['@iri'], usedCtx);
         }
         else
         {
            rval = _compactIri(ctx, rval, usedCtx);
         }
      }
   }

   return rval;
};

/**
 * Recursively expands a value using the given context. Any context in
 * the value will be removed.
 *
 * @param ctx the context.
 * @param property the property that points to the value, NULL for none.
 * @param value the value to expand.
 * @param expandSubjects true to expand subjects (normalize), false not to.
 *
 * @return the expanded value.
 */
var _expand = function(ctx, property, value, expandSubjects)
{
   var rval;
   
   // TODO: add data format error detection?

   // if no property is specified and the value is a string (this means the
   // value is a property itself), expand to an IRI
   if(property === null && value.constructor === String)
   {
      rval = _expandTerm(ctx, value, null);
   }
   else if(value.constructor === Array)
   {
      // recursively add expanded values to array
      rval = [];
      for(var i in value)
      {
         rval.push(_expand(ctx, property, value[i], expandSubjects));
      }
   }
   else if(value.constructor === Object)
   {
      // value has sub-properties if it doesn't define a literal or IRI value
      if(!('@literal' in value || '@iri' in value))
      {
         // if value has a context, use it
         if('@context' in value)
         {
            ctx = jsonld.mergeContexts(ctx, value['@context']);
         }

         // recursively handle sub-properties that aren't a sub-context
         rval = {};
         for(var key in value)
         {
            // preserve frame keywords
            if(key === '@embed' || key === '@explicit')
            {
               _setProperty(rval, key, _clone(value[key]));
            }
            else if(key !== '@context')
            {
               // set object to expanded property
               _setProperty(
                  rval, _expandTerm(ctx, key, null),
                  _expand(ctx, key, value[key], expandSubjects));
            }
         }
      }
      // value is already expanded
      else
      {
         rval = _clone(value);
      }
   }
   else
   {
      // do type coercion
      var coerce = _getCoerceType(ctx, property, null);

      // automatic coercion for basic JSON types
      if(coerce === null &&
         (value.constructor === Number || value.constructor === Boolean))
      {
         if(value.constructor === Boolean)
         {
            coerce = xsd.boolean;
         }
         else if(('' + value).indexOf('.') == -1)
         {
            coerce = xsd.integer;
         }
         else
         {
            coerce = xsd.double;
         }
      }

      // coerce to appropriate datatype, only expand subjects if requested
      if(coerce !== null && (property !== __s || expandSubjects))
      {
         rval = {};
         
         // expand IRI
         if(coerce === xsd.anyURI)
         {
            rval['@iri'] = _expandTerm(ctx, value, null);
         }
         // other datatype
         else
         {
            rval['@datatype'] = coerce;
            if(coerce === xsd.double)
            {
               // do special JSON-LD double format
               value = value.toExponential(6).replace(
                  /(e(?:\+|-))([0-9])$/, '$10$2');
            }
            rval['@literal'] = '' + value;
         }
      }
      // nothing to coerce
      else
      {
         rval = '' + value;
      }
   }
   
   return rval;
};

var _isBlankNodeIri = function(v)
{
   return v.indexOf('_:') === 0;
};

var _isNamedBlankNode = function(v)
{
   // look for "_:" at the beginning of the subject
   return (
      v.constructor === Object && __s in v &&
      '@iri' in v[__s] && _isBlankNodeIri(v[__s]['@iri']));
};

var _isBlankNode = function(v)
{
   // look for no subject or named blank node
   return (
      v.constructor === Object &&
      !('@iri' in v || '@literal' in v) &&
      (!(__s in v) || _isNamedBlankNode(v)));
};

/**
 * Compares two values.
 * 
 * @param v1 the first value.
 * @param v2 the second value.
 * 
 * @return -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
 */
var _compare = function(v1, v2)
{
   var rval = 0;
   
   if(v1.constructor === Array && v2.constructor === Array)
   {
      for(var i = 0; i < v1.length && rval === 0; ++i)
      {
         rval = _compare(v1[i], v2[i]);
      }
   }
   else
   {
      rval = (v1 < v2 ? -1 : (v1 > v2 ? 1 : 0));
   }
   
   return rval;
};

/**
 * Compares two keys in an object. If the key exists in one object
 * and not the other, that object is less. If the key exists in both objects,
 * then the one with the lesser value is less.
 * 
 * @param o1 the first object.
 * @param o2 the second object.
 * @param key the key.
 * 
 * @return -1 if o1 < o2, 0 if o1 == o2, 1 if o1 > o2.
 */
var _compareObjectKeys = function(o1, o2, key)
{
   var rval = 0;
   if(key in o1)
   {
      if(key in o2)
      {
         rval = _compare(o1[key], o2[key]);
      }
      else
      {
         rval = -1;
      }
   }
   else if(key in o2)
   {
      rval = 1;
   }
   return rval;
};

/**
 * Compares two object values.
 * 
 * @param o1 the first object.
 * @param o2 the second object.
 * 
 * @return -1 if o1 < o2, 0 if o1 == o2, 1 if o1 > o2.
 */
var _compareObjects = function(o1, o2)
{
   var rval = 0;
   
   if(o1.constructor === String)
   {
      if(o2.constructor !== String)
      {
         rval = -1;
      }
      else
      {
         rval = _compare(o1, o2);
      }
   }
   else if(o2.constructor === String)
   {
      rval = 1;
   }
   else
   {
      rval = _compareObjectKeys(o1, o2, '@literal');
      if(rval === 0)
      {
         if('@literal' in o1)
         {
            rval = _compareObjectKeys(o1, o2, '@datatype');
            if(rval === 0)
            {
               rval = _compareObjectKeys(o1, o2, '@language');
            }
         }
         // both are '@iri' objects
         else
         {
            rval = _compare(o1['@iri'], o2['@iri']);
         }
      }
   }
   
   return rval;
};

/**
 * Compares the object values between two bnodes.
 * 
 * @param a the first bnode.
 * @param b the second bnode.
 * 
 * @return -1 if a < b, 0 if a == b, 1 if a > b.
 */
var _compareBlankNodeObjects = function(a, b)
{
   var rval = 0;
   
   /*
   3. For each property, compare sorted object values.
   3.1. The bnode with fewer objects is first.
   3.2. For each object value, compare only literals and non-bnodes.
   3.2.1.  The bnode with fewer non-bnodes is first.
   3.2.2. The bnode with a string object is first.
   3.2.3. The bnode with the alphabetically-first string is first.
   3.2.4. The bnode with a @literal is first.
   3.2.5. The bnode with the alphabetically-first @literal is first.
   3.2.6. The bnode with the alphabetically-first @datatype is first.
   3.2.7. The bnode with a @language is first.
   3.2.8. The bnode with the alphabetically-first @language is first.
   3.2.9. The bnode with the alphabetically-first @iri is first.
   */
   
   for(var p in a)
   {
      // step #3.1
      var lenA = (a[p].constructor === Array) ? a[p].length : 1;
      var lenB = (b[p].constructor === Array) ? b[p].length : 1;
      rval = _compare(lenA, lenB);
      
      // step #3.2.1
      if(rval === 0)
      {
         // normalize objects to an array
         var objsA = a[p];
         var objsB = b[p];
         if(objsA.constructor !== Array)
         {
            objsA = [objsA];
            objsB = [objsB];
         }
         
         // filter non-bnodes (remove bnodes from comparison)
         objsA = objsA.filter(function(e) {
            return (e.constructor === String ||
               !('@iri' in e && _isBlankNodeIri(e['@iri'])));
         });
         objsB = objsB.filter(function(e) {
            return (e.constructor === String ||
               !('@iri' in e && _isBlankNodeIri(e['@iri'])));
         });
         
         rval = _compare(objsA.length, objsB.length);
      }
      
      // steps #3.2.2-3.2.9
      if(rval === 0)
      {
         objsA.sort(_compareObjects);
         objsB.sort(_compareObjects);
         for(var i = 0; i < objsA.length && rval === 0; ++i)
         {
            rval = _compareObjects(objsA[i], objsB[i]);
         }
      }
      
      if(rval !== 0)
      {
         break;
      }
   }
   
   return rval;
};

/**
 * Creates a blank node name generator using the given prefix for the
 * blank nodes. 
 * 
 * @param prefix the prefix to use.
 * 
 * @return the blank node name generator.
 */
var _createNameGenerator = function(prefix)
{
   var count = -1;
   var ng = {
      next: function()
      {
         ++count;
         return ng.current();
      },
      current: function()
      {
         return '_:' + prefix + count;
      },
      inNamespace: function(iri)
      {
         return iri.indexOf('_:' + prefix) === 0;
      }
   };
   return ng;
};

/**
 * Populates a map of all named subjects from the given input and an array
 * of all unnamed bnodes (includes embedded ones).
 * 
 * @param input the input (must be expanded, no context).
 * @param subjects the subjects map to populate.
 * @param bnodes the bnodes array to populate.
 */
var _collectSubjects = function(input, subjects, bnodes)
{
   if(input.constructor === Array)
   {
      for(var i in input)
      {
         _collectSubjects(input[i], subjects, bnodes);
      }
   }
   else if(input.constructor === Object)
   {
      if(__s in input)
      {
         // graph literal
         if(input[__s].constructor == Array)
         {
            _collectSubjects(input[__s], subjects, bnodes);
         }
         // named subject
         else
         {
            subjects[input[__s]['@iri']] = input;
         }
      }
      // unnamed blank node
      else if(_isBlankNode(input))
      {
         bnodes.push(input);
      }
      
      // recurse through subject properties
      for(var key in input)
      {
         _collectSubjects(input[key], subjects, bnodes);
      }
   }
};

/**
 * Flattens the given value into a map of unique subjects. It is assumed that
 * all blank nodes have been uniquely named before this call. Array values for
 * properties will be sorted.
 *
 * @param parent the value's parent, NULL for none.
 * @param parentProperty the property relating the value to the parent.
 * @param value the value to flatten.
 * @param subjects the map of subjects to write to.
 */
var _flatten = function(parent, parentProperty, value, subjects)
{
   var flattened = null;
   
   if(value.constructor === Array)
   {
      // list of objects or a disjoint graph
      for(var i in value)
      {
         _flatten(parent, parentProperty, value[i], subjects);
      }
      
      // if value is a list of objects, sort them
      if(value.length > 0 &&
         (value[0].constructor === String ||
         (value[0].constructor === Object &&
         ('@literal' in value[0] || '@iri' in value[0]))))
      {
         // sort values
         value.sort(_compareObjects);
      }
   }
   else if(value.constructor === Object)
   {
      // graph literal/disjoint graph
      if(__s in value && value[__s].constructor === Array)
      {
         // cannot flatten embedded graph literals
         if(parent !== null)
         {
            throw {
               message: 'Embedded graph literals cannot be flattened.'
            };
         }
         
         // top-level graph literal
         for(var key in value[__s])
         {
            _flatten(parent, parentProperty, value[__s][key], subjects);
         }
      }
      // already-expanded value
      else if('@literal' in value || '@iri' in value)
      {
         flattened = _clone(value);
      }
      // subject
      else
      {
         // create or fetch existing subject
         var subject;
         if(value[__s]['@iri'] in subjects)
         {
            // FIXME: __s might be a graph literal (as {})
            subject = subjects[value[__s]['@iri']];
         }
         else
         {
            subject = {};
            if(__s in value)
            {
               // FIXME: __s might be a graph literal (as {})
               subjects[value[__s]['@iri']] = subject;
            }
         }
         flattened = subject;

         // flatten embeds
         for(var key in value)
         {
            if(value[key].constructor === Array)
            {
               subject[key] = [];
               _flatten(subject[key], null, value[key], subjects);
               if(subject[key].length === 1)
               {
                  // convert subject[key] to object if only 1 value was added
                  subject[key] = subject[key][0];
               }
            }
            else
            {
               _flatten(subject, key, value[key], subjects);
            }
         }
      }
   }
   // string value
   else
   {
      flattened = value;
   }

   // add flattened value to parent
   if(flattened !== null && parent !== null)
   {
      // remove top-level __s for subjects
      // 'http://mypredicate': {'@subject': {'@iri': 'http://mysubject'}}
      // becomes
      // 'http://mypredicate': {'@iri': 'http://mysubject'}
      if(flattened.constructor === Object && __s in flattened)
      {
         flattened = flattened[__s];
      }

      if(parent.constructor === Array)
      {
         // do not add duplicate IRIs for the same property
         var duplicate = false;
         if(flattened.constructor === Object && '@iri' in flattened)
         {
            duplicate = (parent.filter(function(e)
            {
               return (e.constructor === Object && '@iri' in e &&
                  e['@iri'] === flattened['@iri']);
            }).length > 0);
         }
         if(!duplicate)
         {
            parent.push(flattened);
         }
      }
      else
      {
         parent[parentProperty] = flattened;
      }
   }
};

/**
 * Constructs a new JSON-LD processor.
 */
jsonld.Processor = function()
{
   this.ng =
   {
      tmp: null,
      c14n: null
   };
};

/**
 * Normalizes a JSON-LD object.
 *
 * @param input the JSON-LD object to normalize.
 * 
 * @return the normalized JSON-LD object.
 */
jsonld.Processor.prototype.normalize = function(input)
{
   var rval = [];

   // TODO: validate context

   if(input !== null)
   {
      // get default context
      var ctx = _createDefaultContext();

      // expand input
      var expanded = _expand(ctx, null, input, true);
      
      // assign names to unnamed bnodes
      this.nameBlankNodes(expanded);

      // flatten
      var subjects = {};
      _flatten(null, null, expanded, subjects);

      // append subjects with sorted properties to array
      for(var key in subjects)
      {
         var s = subjects[key];
         var sorted = {};
         var keys = Object.keys(s).sort();
         for(var i in keys)
         {
            var k = keys[i];
            sorted[k] = s[k];
         }
         rval.push(sorted);
      }

      // canonicalize blank nodes
      this.canonicalizeBlankNodes(rval);

      // sort output
      rval.sort(function(a, b)
      {
         return _compare(a[__s]['@iri'], b[__s]['@iri']);
      });
   }

   return rval;
};

/**
 * Assigns unique names to blank nodes that are unnamed in the given input.
 * 
 * @param input the input to assign names to.
 */
jsonld.Processor.prototype.nameBlankNodes = function(input)
{
   // create temporary blank node name generator
   var ng = this.ng.tmp = _createNameGenerator('tmp');
   
   // collect subjects and unnamed bnodes
   var subjects = {};
   var bnodes = [];
   _collectSubjects(input, subjects, bnodes);
   
   // uniquely name all unnamed bnodes
   for(var i in bnodes)
   {
      var bnode = bnodes[i];
      if(!(__s in bnode))
      {
         // generate names until one is unique
         while(ng.next() in subjects);
         bnode[__s] =
         {
            '@iri': ng.current()
         };
         subjects[ng.current()] = bnode;
      }
   }
};

/**
 * Renames a blank node, changing its references, etc. The method assumes
 * that the given name is unique.
 * 
 * @param b the blank node to rename.
 * @param id the new name to use.
 */
jsonld.Processor.prototype.renameBlankNode = function(b, id)
{
   var old = b[__s]['@iri'];
   
   // update bnode IRI
   b[__s]['@iri'] = id;
   
   // update subjects map
   var subjects = this.subjects;
   subjects[id] = subjects[old];
   delete subjects[old];
   
   // update reference and property lists
   this.edges.refs[id] = this.edges.refs[old];
   this.edges.props[id] = this.edges.props[old];
   delete this.edges.refs[old];
   delete this.edges.props[old];
   
   // update references to this bnode
   var refs = this.edges.refs[id].all;
   for(var i in refs)
   {
      var iri = refs[i].s;
      if(iri === old)
      {
         iri = id;
      }
      var ref = subjects[iri];
      var props = this.edges.props[iri].all;
      for(var i2 in props)
      {
         if(props[i2].s === old)
         {
            props[i2].s = id;
            
            // normalize property to array for single code-path
            var p = props[i2].p;
            var tmp = (ref[p].constructor === Object) ? [ref[p]] :
               (ref[p].constructor === Array) ? ref[p] : [];
            for(var n in tmp)
            {
               if(tmp[n].constructor === Object &&
                  '@iri' in tmp[n] && tmp[n]['@iri'] === old)
               {
                  tmp[n]['@iri'] = id;
               }
            }
         }
      }
   }
   
   // update references from this bnode 
   var props = this.edges.props[id].all;
   for(var i in props)
   {
      var iri = props[i].s;
      refs = this.edges.refs[iri].all;
      for(var r in refs)
      {
         if(refs[r].s === old)
         {
            refs[r].s = id;
         }
      }
   }
};

/**
 * Canonically names blank nodes in the given input.
 * 
 * @param input the flat input graph to assign names to.
 */
jsonld.Processor.prototype.canonicalizeBlankNodes = function(input)
{
   // create serialization state
   this.renamed = {};
   this.mappings = {};
   this.serializations = {};
   
   // collect subjects and bnodes from flat input graph
   var edges = this.edges =
   {
      refs: {},
      props: {}
   };
   var subjects = this.subjects = {};
   var bnodes = [];
   for(var i in input)
   {
      var iri = input[i][__s]['@iri'];
      subjects[iri] = input[i];
      edges.refs[iri] =
      {
         all: [],
         bnodes: []
      };
      edges.props[iri] =
      {
         all: [],
         bnodes: []
      };
      if(_isBlankNodeIri(iri))
      {
         bnodes.push(input[i]);
      }
   }
   
   // collect edges in the graph
   this.collectEdges();
   
   // create canonical blank node name generator
   var c14n = this.ng.c14n = _createNameGenerator('c14n');
   var ngTmp = this.ng.tmp;
   
   // rename all bnodes that happen to be in the c14n namespace
   // and initialize serializations
   for(var i in bnodes)
   {
      var bnode = bnodes[i];
      var iri = bnode[__s]['@iri'];
      if(c14n.inNamespace(iri))
      {
         // generate names until one is unique
         while(ngTmp.next() in subjects);
         this.renameBlankNode(bnode, ngTmp.current());
         iri = bnode[__s]['@iri'];
      }
      this.serializations[iri] =
      {
         'props': null,
         'refs': null
      };
   }
   
   // keep sorting and naming blank nodes until they are all named
   var self = this;
   while(bnodes.length > 0)
   {
      bnodes.sort(function(a, b)
      {
         return self.deepCompareBlankNodes(a, b);
      });
      
      // name all bnodes according to the first bnode's relation mappings
      var bnode = bnodes.shift();
      var iri = bnode[__s]['@iri'];
      var dirs = ['props', 'refs'];
      for(var d in dirs)
      {
         var dir = dirs[d];
         
         // if no serialization has been computed, name only the first node
         if(this.serializations[iri][dir] === null)
         {
            var mapping = {};
            mapping[iri] = 's1';
         }
         else
         {
            mapping = this.serializations[iri][dir].m;
         }
         
         // sort keys by value to name them in order
         var keys = Object.keys(mapping);
         keys.sort(function(a, b)
         {
            return _compare(mapping[a], mapping[b]);
         });
         
         // name bnodes in mapping
         var renamed = [];
         for(var i in keys)
         {
            var iriK = keys[i];
            if(!c14n.inNamespace(iri) && iriK in subjects)
            {
               this.renameBlankNode(subjects[iriK], c14n.next());
               renamed.push(iriK);
            }
         }
         
         // only keep non-canonically named bnodes
         var tmp = bnodes;
         bnodes = [];
         for(var i in tmp)
         {
            var b = tmp[i];
            var iriB = b[__s]['@iri'];
            if(!c14n.inNamespace(iriB))
            {
               // mark serializations related to the named bnodes as dirty
               for(var i2 in renamed)
               {
                  this.markSerializationDirty(iriB, renamed[i2], dir);
               }
               bnodes.push(b);
            }
         }
      }
   }
   
   // sort property lists that now have canonically-named bnodes
   for(var key in edges.props)
   {
      if(edges.props[key].bnodes.length > 0)
      {
         var bnode = subjects[key];
         for(var p in bnode)
         {
            if(p.indexOf('@') !== 0 && bnode[p].constructor === Array)
            {
               bnode[p].sort(_compareObjects);
            }
         }
      }
   }
};

/**
 * A MappingBuilder is used to build a mapping of existing blank node names
 * to a form for serialization. The serialization is used to compare blank
 * nodes against one another to determine a sort order.
 */
MappingBuilder = function()
{
   this.count = 1;
   this.mapped = {};
   this.mapping = {};
   this.output = {};
};

/**
 * Copies this MappingBuilder.
 * 
 * @return the MappingBuilder copy.
 */
MappingBuilder.prototype.copy = function()
{
   var rval = new MappingBuilder();
   rval.count = this.count;
   rval.mapped = _clone(this.mapped);
   rval.mapping = _clone(this.mapping);
   rval.output = _clone(this.output);
   return rval;
};

/**
 * Maps the next name to the given bnode IRI if the bnode IRI isn't already in
 * the mapping. If the given bnode IRI is canonical, then it will be given
 * a shortened form of the same name.
 * 
 * @param iri the blank node IRI to map the next name to.
 * 
 * @return the mapped name.
 */
MappingBuilder.prototype.mapNode = function(iri)
{
   if(!(iri in this.mapping))
   {
      if(iri.indexOf('_:c14n') === 0)
      {
         this.mapping[iri] = 'c' + iri.substr(6);
      }
      else
      {
         this.mapping[iri] = 's' + this.count++;
      }
   }
   return this.mapping[iri];
};

/**
 * Marks a relation serialization as dirty if necessary.
 * 
 * @param iri the IRI of the bnode to check.
 * @param changed the old IRI of the bnode that changed.
 * @param dir the direction to check ('props' or 'refs').
 */
jsonld.Processor.prototype.markSerializationDirty = function(iri, changed, dir)
{
   var s = this.serializations[iri];
   if(s[dir] !== null && changed in s[dir].m)
   {
      s[dir] = null;
   }
};

/**
 * Rotates the elements in an array one position.
 * 
 * @param a the array.
 */
var _rotate = function(a)
{
   a.unshift.apply(a, a.splice(1, a.length));
};

/**
 * Serializes the properties of the given bnode for its relation serialization.
 * 
 * @param b the blank node.
 * 
 * @return the serialized properties.
 */
var _serializeProperties = function(b)
{
   var rval = '';
   
   for(var p in b)
   {
      if(p !== '@subject')
      {
         var first = true;
         var objs = (b[p].constructor === Array) ? b[p] : [b[p]];
         for(var oi in objs)
         {
            if(first)
            {
               first = false;
            }
            else
            {
               rval += '|';
            }
            if(objs[oi].constructor === Object &&
               '@iri' in objs[oi] && _isBlankNodeIri(objs[oi]['@iri']))
            {
               rval += '_:';
            }
            else
            {
               rval += JSON.stringify(objs[oi]);
            }
         }
      }
   }
   
   return rval;
};

/**
 * Recursively creates a relation serialization (partial or full).
 * 
 * @param keys the keys to serialize in the current output.
 * @param output the current mapping builder output.
 * @param done the already serialized keys.
 * 
 * @return the relation serialization.
 */
jsonld.Processor.prototype.recursiveSerializeMapping = function(
   keys, output, done)
{
   var rval = '';
   for(var i in keys)
   {
      var k = keys[i];
      if(!(k in output))
      {
         break;
      }
      
      if(k in done)
      {
         // mark cycle
         rval += '_' + k;
      }
      else
      {
         done[k] = true;
         var tmp = output[k];
         for(var t in tmp.k)
         {
            var s = tmp.k[t]; 
            rval += s;
            var iri = tmp.m[s];
            if(iri in this.subjects)
            {
               var b = this.subjects[iri];
               
               // serialize properties
               rval += '<';
               rval += _serializeProperties(b);
               rval += '>';
               
               // serialize references
               rval += '<';
               var first = true;
               var refs = this.edges.refs[iri].all;
               for(var r in refs)
               {
                  if(first)
                  {
                     first = false;
                  }
                  else
                  {
                     rval += '|';
                  }
                  rval += _isBlankNodeIri(refs[r].s) ? '_:' : refs[r].s;
               }
               rval += '>';
            }
         }
         rval += this.recursiveSerializeMapping(tmp.k, output, done);
      }
   }
   return rval;
};

/**
 * Creates a relation serialization (partial or full).
 * 
 * @param output the current mapping builder output.
 * 
 * @return the relation serialization.
 */
jsonld.Processor.prototype.serializeMapping = function(output)
{
   return this.recursiveSerializeMapping(['s1'], output, {});
};

/**
 * Compares two serializations for the same blank node. If the two
 * serializations aren't complete enough to determine if they are equal (or if
 * they are actually equal), 0 is returned.
 * 
 * @param s1 the first serialization.
 * @param s2 the second serialization.
 * 
 * @return -1 if s1 < s2, 0 if s1 == s2 (or indeterminate), 1 if s1 > v2.
 */
var _compareSerializations = function(s1, s2)
{
   var rval = 0;
   
   if(s1.length == s2.length)
   {
      rval = _compare(s1, s2);
   }
   else if(s1.length > s2.length)
   {
      rval = _compare(s1.substr(0, s2.length), s2);
   }
   else
   {
      rval = _compare(s1, s2.substr(0, s1.length));
   }
   
   return rval;
};

/**
 * Recursively serializes adjacent bnode combinations.
 * 
 * @param s the serialization to update.
 * @param top the top of the serialization.
 * @param mb the MappingBuilder to use.
 * @param dir the edge direction to use ('props' or 'refs').
 * @param mapped all of the already-mapped adjacent bnodes.
 * @param notMapped all of the not-yet mapped adjacent bnodes.
 */
jsonld.Processor.prototype.serializeCombos = function(
   s, top, mb, dir, mapped, notMapped)
{
   // copy mapped nodes
   mapped = _clone(mapped);
   
   // handle recursion
   if(notMapped.length > 0)
   {
      // map first bnode in list
      mapped[mb.mapNode(notMapped[0].s)] = notMapped[0].s;
      
      // recurse into remaining possible combinations
      var original = mb.copy();
      notMapped = notMapped.slice(1);
      var rotations = Math.max(1, notMapped.length);
      for(var r = 0; r < rotations; ++r)
      {
         var m = (r === 0) ? mb : original.copy();
         this.serializeCombos(s, top, m, dir, mapped, notMapped);
         
         // rotate not-mapped for next combination
         _rotate(notMapped);
      }
   }
   // handle final adjacent node in current combination
   else
   {
      var keys = Object.keys(mapped).sort();
      mb.output[top] = { k: keys, m: mapped };
      
      // optimize away mappings that are already too large
      var _s = this.serializeMapping(mb.output);
      if(s[dir] === null || _compareSerializations(_s, s[dir].s) <= 0)
      {
         var oldCount = mb.count;
         
         // recurse into adjacent values
         for(var i in keys)
         {
            var k = keys[i];
            this.serializeBlankNode(s, mapped[k], mb, dir);
         }
         
         // reserialize if more nodes were mapped
         if(mb.count > oldCount)
         {
            _s = this.serializeMapping(mb.output);
         }
         
         // update least serialization if new one has been found
         if(s[dir] === null ||
            (_compareSerializations(_s, s[dir].s) <= 0 &&
            _s.length >= s[dir].s.length))
         {
            s[dir] = { s: _s, m: mb.mapping };
         }
      }
   }
};

/**
 * Computes the relation serialization for the given blank node IRI.
 * 
 * @param s the serialization to update.
 * @param iri the current bnode IRI to be mapped.
 * @param mb the MappingBuilder to use.
 * @param dir the edge direction to use ('props' or 'refs').
 */
jsonld.Processor.prototype.serializeBlankNode = function(s, iri, mb, dir)
{
   // only do mapping if iri not already mapped
   if(!(iri in mb.mapped))
   {
      // iri now mapped
      mb.mapped[iri] = true;
      var top = mb.mapNode(iri);
      
      // copy original mapping builder
      var original = mb.copy();
      
      // split adjacent bnodes on mapped and not-mapped
      var adj = this.edges[dir][iri].bnodes;
      var mapped = {};
      var notMapped = [];
      for(var i in adj)
      {
         if(adj[i].s in mb.mapping)
         {
            mapped[mb.mapping[adj[i].s]] = adj[i].s;
         }
         else
         {
            notMapped.push(adj[i]);
         }
      }
      
      // TODO: ensure this optimization does not alter canonical order
      
      // if the current bnode already has a serialization, reuse it
      /*var hint = (iri in this.serializations) ?
         this.serializations[iri][dir] : null;
      if(hint !== null)
      {
         var hm = hint.m;
         notMapped.sort(function(a, b)
         {
            return _compare(hm[a.s], hm[b.s]);
         });
         for(var i in notMapped)
         {
            mapped[mb.mapNode(notMapped[i].s)] = notMapped[i].s;
         }
         notMapped = [];
      }*/
      
      // loop over possible combinations
      var combos = Math.max(1, notMapped.length);
      for(var i = 0; i < combos; ++i)
      {
         var m = (i === 0) ? mb : original.copy();
         this.serializeCombos(s, top, mb, dir, mapped, notMapped);         
      }
   }
};

/**
 * Compares two blank nodes for equivalence.
 * 
 * @param a the first blank node.
 * @param b the second blank node.
 * 
 * @return -1 if a < b, 0 if a == b, 1 if a > b.
 */
jsonld.Processor.prototype.deepCompareBlankNodes = function(a, b)
{
   var rval = 0;
   
   // compare IRIs
   var iriA = a[__s]['@iri'];
   var iriB = b[__s]['@iri'];
   if(iriA === iriB)
   {
      rval = 0;
   }
   else
   {
      // do shallow compare first
      rval = this.shallowCompareBlankNodes(a, b);
      
      // deep comparison is necessary
      if(rval === 0)
      {
         // compare property edges and then reference edges
         var dirs = ['props', 'refs'];
         for(var i = 0; rval === 0 && i < dirs.length; ++i)
         {
            // recompute 'a' and 'b' serializations as necessary
            var dir = dirs[i];
            var sA = this.serializations[iriA];
            var sB = this.serializations[iriB];
            if(sA[dir] === null)
            {
               var mb = new MappingBuilder();
               if(dir === 'refs')
               {
                  // keep same mapping and count from 'props' serialization
                  mb.mapping = _clone(sA['props'].m);
                  mb.count = Object.keys(mb.mapping).length + 1;
               }
               this.serializeBlankNode(sA, iriA, mb, dir);
            }
            if(sB[dir] === null)
            {
               var mb = new MappingBuilder();
               if(dir === 'refs')
               {
                  // keep same mapping and count from 'props' serialization
                  mb.mapping = _clone(sB['props'].m);
                  mb.count = Object.keys(mb.mapping).length + 1;
               }
               this.serializeBlankNode(sB, iriB, mb, dir);
            }
            
            // compare serializations
            rval = _compare(sA[dir].s, sB[dir].s);
         }
      }
   }
   
   return rval;
};

/**
 * Performs a shallow sort comparison on the given bnodes.
 * 
 * @param a the first bnode.
 * @param b the second bnode.
 * 
 * @return -1 if a < b, 0 if a == b, 1 if a > b.
 */
jsonld.Processor.prototype.shallowCompareBlankNodes = function(a, b)
{
   var rval = 0;
   
   /* ShallowSort Algorithm (when comparing two bnodes):
      1. Compare the number of properties.
      1.1. The bnode with fewer properties is first.
      2. Compare alphabetically sorted-properties.
      2.1. The bnode with the alphabetically-first property is first.
      3. For each property, compare object values.
      4. Compare the number of references.
      4.1. The bnode with fewer references is first.
      5. Compare sorted references.
      5.1. The bnode with the reference iri (vs. bnode) is first.
      5.2. The bnode with the alphabetically-first reference iri is first.
      5.3. The bnode with the alphabetically-first reference property is first.
    */
   var pA = Object.keys(a);
   var pB = Object.keys(b);
   
   // step #1
   rval = _compare(pA.length, pB.length);
   
   // step #2
   if(rval === 0)
   {
      rval = _compare(pA.sort(), pB.sort());
   }
   
   // step #3
   if(rval === 0)
   {
      rval = _compareBlankNodeObjects(a, b);
   }
   
   // step #4
   if(rval === 0)
   {
      var edgesA = this.edges.refs[a[__s]['@iri']].all;
      var edgesB = this.edges.refs[b[__s]['@iri']].all;
      rval = _compare(edgesA.length, edgesB.length);
   }
   
   // step #5
   if(rval === 0)
   {
      for(var i = 0; i < edgesA.length && rval === 0; ++i)
      {
         rval = this.compareEdges(edgesA[i], edgesB[i]);
      }
   }
   
   return rval;
};

/**
 * Compares two edges. Edges with an IRI (vs. a bnode ID) come first, then
 * alphabetically-first IRIs, then alphabetically-first properties. If a blank
 * node has been canonically named, then blank nodes will be compared after
 * properties (with a preference for canonically named over non-canonically
 * named), otherwise they won't be.
 * 
 * @param a the first edge.
 * @param b the second edge.
 * 
 * @return -1 if a < b, 0 if a == b, 1 if a > b.
 */
jsonld.Processor.prototype.compareEdges = function(a, b)
{
   var rval = 0;
   
   var bnodeA = _isBlankNodeIri(a.s);
   var bnodeB = _isBlankNodeIri(b.s);
   var c14n = this.ng.c14n;
   
   // if not both bnodes, one that is a bnode is greater
   if(bnodeA != bnodeB)
   {
      rval = bnodeA ? 1 : -1;
   }
   else
   {
      if(!bnodeA)
      {
         rval = _compare(a.s, b.s);
      }
      if(rval === 0)
      {
         rval = _compare(a.p, b.p);
      }
      
      // do bnode IRI comparison if canonical naming has begun
      if(rval === 0 && c14n !== null)
      {
         var c14nA = c14n.inNamespace(a.s);
         var c14nB = c14n.inNamespace(b.s);
         if(c14nA != c14nB)
         {
            rval = c14nA ? 1 : -1;
         }
         else if(c14nA)
         {
            rval = _compare(a.s, b.s);
         }
      }
   }
   
   return rval;
};

/**
 * Populates the given reference map with all of the subject edges in the
 * graph. The references will be categorized by the direction of the edges,
 * where 'props' is for properties and 'refs' is for references to a subject as
 * an object. The edge direction categories for each IRI will be sorted into
 * groups 'all' and 'bnodes'.
 */
jsonld.Processor.prototype.collectEdges = function()
{
   var refs = this.edges.refs;
   var props = this.edges.props;
   
   // collect all references and properties
   for(var iri in this.subjects)
   {
      var subject = this.subjects[iri];
      for(var key in subject)
      {
         if(key !== __s)
         {
            // normalize to array for single codepath
            var object = subject[key];
            var tmp = (object.constructor !== Array) ? [object] : object;
            for(var i in tmp)
            {
               var o = tmp[i];
               if(o.constructor === Object && '@iri' in o &&
                  o['@iri'] in this.subjects)
               {
                  var objIri = o['@iri'];
                  
                  // map object to this subject
                  refs[objIri].all.push({ s: iri, p: key });
                  
                  // map this subject to object
                  props[iri].all.push({ s: objIri, p: key });
               }
            }
         }
      }
   }
   
   // create sorted categories
   var self = this;
   for(var iri in refs)
   {
      refs[iri].all.sort(function(a, b) { return self.compareEdges(a, b); });
      refs[iri].bnodes = refs[iri].all.filter(function(edge) {
         return _isBlankNodeIri(edge.s)
      });
   }
   for(var iri in props)
   {
      props[iri].all.sort(function(a, b) { return self.compareEdges(a, b); });
      props[iri].bnodes = props[iri].all.filter(function(edge) {
         return _isBlankNodeIri(edge.s);
      });
   }
};

/**
 * Returns true if the given input is a subject and has one of the given types
 * in the given frame.
 * 
 * @param input the input.
 * @param frame the frame with types to look for.
 * 
 * @return true if the input has one of the given types.
 */
var _isType = function(input, frame)
{
   var rval = false;
   
   // check if type(s) are specified in frame and input
   var type = jsonld.ns.rdf + 'type';
   if(type in frame &&
      input.constructor === Object && __s in input && type in input)
   {
      var tmp = (input[type].constructor === Array) ?
         input[type] : [input[type]];
      var types = (frame[type].constructor === Array) ?
         frame[type] : [frame[type]];
      for(var t = 0; t < types.length && !rval; ++t)
      {
         type = types[t]['@iri'];
         for(var i in tmp)
         {
            if(tmp[i]['@iri'] === type)
            {
               rval = true;
               break;
            }
         }
      }
   }
   
   return rval;
};

/**
 * Returns true if the given input matches the given frame via duck-typing.
 * 
 * @param input the input.
 * @param frame the frame to check against.
 * 
 * @return true if the input matches the frame.
 */
var _isDuckType = function(input, frame)
{
   var rval = false;
   
   // frame must not have a specific type
   var type = jsonld.ns.rdf + 'type';
   if(!(type in frame))
   {
      // get frame properties that must exist on input
      var props = Object.keys(frame);
      if(props.length === 0)
      {
         // input always matches if there are no properties
         rval = true;
      }
      // input must be a subject with all the given properties
      else if(input.constructor === Object && __s in input)
      {
         rval = true;
         for(var i in props)
         {
            if(!(props[i] in input))
            {
               rval = false;
               break;
            }
         }
      }
   }
   
   return rval;
};

/**
 * Recursively frames the given input according to the given frame.
 * 
 * @param subjects a map of subjects in the graph.
 * @param input the input to frame.
 * @param frame the frame to use.
 * @param embeds a map of previously embedded subjects, used to prevent cycles.
 * @param options the framing options.
 * 
 * @return the framed input.
 */
var _frame = function(subjects, input, frame, embeds, options)
{
   var rval = null;
   
   // prepare output, set limit, get array of frames
   var limit = -1;
   var frames;
   if(frame.constructor === Array)
   {
      rval = [];
      frames = frame;
   }
   else
   {
      frames = [frame];
      limit = 1;
   }
   
   // iterate over frames adding input matches to list
   var values = [];
   for(var i = 0; i < frames.length && limit !== 0; ++i)
   {
      // get next frame
      frame = frames[i];
      if(frame.constructor !== Object)
      {
         throw {
            message: 'Invalid JSON-LD frame. Frame type is not a map or array.'
         };
      }
      
      // create array of values for each frame
      values[i] = [];
      for(var n = 0; n < input.length && limit !== 0; ++n)
      {
         // add input to list if it matches frame specific type or duck-type
         if(_isType(input[n], frame) || _isDuckType(input[n], frame))
         {
            values[i].push(input[n]);
            --limit;
         }
      }
   }
   
   // for each matching value, add it to the output
   for(var i1 in values)
   {
      for(var i2 in values[i1])
      {
         frame = frames[i1];
         var value = values[i1][i2];
         
         // determine if value should be embedded or referenced
         var embedOn = ('@embed' in frame) ?
            frame['@embed'] : options.defaults.embedOn;
         if(!embedOn)
         {
            // if value is a subject, only use subject IRI as reference 
            if(value.constructor === Object && __s in value)
            {
               value = value[__s];
            }
         }
         else if(
            value.constructor === Object &&
            __s in value && value[__s]['@iri'] in embeds)
         {
            // TODO: possibly support multiple embeds in the future ... and
            // instead only prevent cycles?
            throw {
               message: 'Multiple embeds of the same subject is not supported.',
               subject: value[__s]['@iri']
            };
         }
         // if value is a subject, do embedding and subframing
         else if(value.constructor === Object && __s in value)
         {
            embeds[value[__s]['@iri']] = true;
            
            // if explicit is on, remove keys from value that aren't in frame
            var explicitOn = ('@explicit' in frame) ?
               frame['@explicit'] : options.defaults.explicitOn;
            if(explicitOn)
            {
               for(key in value)
               {
                  // always include subject
                  if(key !== __s && !(key in frame))
                  {
                     delete value[key];
                  }
               }
            }
            
            // iterate over frame keys to do subframing
            for(key in frame)
            {
               // skip keywords and type query
               if(key.indexOf('@') !== 0 && key !== jsonld.ns.rdf + 'type')
               {
                  if(key in value)
                  {
                     // build input and do recursion
                     input = (value[key].constructor === Array) ?
                        value[key] : [value[key]];
                     for(var n in input)
                     {
                        // replace reference to subject w/subject
                        if(input[n].constructor === Object &&
                           '@iri' in input[n] && input[n]['@iri'] in subjects)
                        {
                           input[n] = subjects[input[n]['@iri']];
                        }
                     }
                     value[key] = _frame(
                        subjects, input, frame[key], embeds, options);
                  }
                  else
                  {
                     // add null property to value
                     value[key] = null;
                  }
               }
            }
         }
         
         // add value to output
         if(rval === null)
         {
            rval = value;
         }
         else
         {
            rval.push(value);
         }
      }
   }
   
   return rval;
};

/**
 * Frames JSON-LD input.
 * 
 * @param input the JSON-LD input.
 * @param frame the frame to use.
 * @param options framing options to use.
 * 
 * @return the framed output.
 */
jsonld.Processor.prototype.frame = function(input, frame, options)
{
   var rval;
   
   // normalize input
   input = jsonld.normalize(input);
   
   // save frame context
   var ctx = null;
   if('@context' in frame)
   {
      ctx = jsonld.mergeContexts(_createDefaultContext(), frame['@context']);
   }
   
   // remove context from frame
   frame = jsonld.removeContext(frame);
   
   // create framing options
   // TODO: merge in options from function parameter
   options =
   {
      defaults:
      {
         embedOn: true,
         explicitOn: false
      }
   };
   
   // build map of all subjects
   var subjects = {};
   for(var i in input)
   {
      subjects[input[i][__s]['@iri']] = input[i];
   }
   
   // frame input
   rval = _frame(subjects, input, frame, {}, options);
   
   // apply context
   if(ctx !== null && rval !== null)
   {
      rval = jsonld.addContext(ctx, rval);
   }
   
   return rval;
};

/**
 * Normalizes a JSON-LD object.
 *
 * @param input the JSON-LD object to normalize.
 * 
 * @return the normalized JSON-LD object.
 */
jsonld.normalize = function(input)
{
   return new jsonld.Processor().normalize(input);
};

/**
 * Removes the context from a JSON-LD object.
 *
 * @param input the JSON-LD object to remove the context from.
 * 
 * @return the context-neutral JSON-LD object.
 */
jsonld.expand = jsonld.removeContext = function(input)
{
   var rval = null;
   
   if(input !== null)
   {
      var ctx = _createDefaultContext();
      rval = _expand(ctx, null, input, false);
   }

   return rval;
};

/**
 * Adds the given context to the given context-neutral JSON-LD object.
 *
 * @param ctx the new context to use.
 * @param input the context-neutral JSON-LD object to add the context to.
 * 
 * @return the JSON-LD object with the new context.
 */
jsonld.addContext = function(ctx, input)
{
   var rval;

   // TODO: should context simplification be optional? (ie: remove context
   // entries that are not used in the output)
   
   ctx = jsonld.mergeContexts(_createDefaultContext(), ctx);
   
   // setup output context
   var ctxOut = {};
   
   // compact
   rval = _compact(ctx, null, input, ctxOut);
   
   // add context if used
   if(Object.keys(ctxOut).length > 0)
   {
      // add copy of context to every entry in output array
      if(rval.constructor === Array)
      {
         for(var i in rval)
         {
            rval[i]['@context'] = _cloneContext(ctxOut);
         }
      }
      else
      {
         rval['@context'] = ctxOut;
      }
   }

   return rval;
};

/**
 * Changes the context of JSON-LD object "input" to "context", returning the
 * output.
 *
 * @param ctx the new context to use.
 * @param input the input JSON-LD object.
 * 
 * @return the output JSON-LD object.
 */
jsonld.compact = jsonld.changeContext = function(ctx, input)
{
   // remove context and then add new one
   return jsonld.addContext(ctx, jsonld.removeContext(input));
};

/**
 * Merges one context with another.
 *
 * @param ctx1 the context to overwrite/append to.
 * @param ctx2 the new context to merge onto ctx1.
 *
 * @return the merged context.
 */
jsonld.mergeContexts = function(ctx1, ctx2)
{
   // copy contexts
   var merged = _cloneContext(ctx1);
   var copy = _cloneContext(ctx2);

   // if the new context contains any IRIs that are in the merged context,
   // remove them from the merged context, they will be overwritten
   for(var key in copy)
   {
      // ignore special keys starting with '@'
      if(key.indexOf('@') !== 0)
      {
         for(var mkey in merged)
         {
            if(merged[mkey] === copy[key])
            {
               delete merged[mkey];
               break;
            }
         }
      }
   }

   // @coerce must be specially-merged, remove from contexts
   var coerceExists = ('@coerce' in merged) || ('@coerce' in copy);
   if(coerceExists)
   {
      var c1 = ('@coerce' in merged) ? merged['@coerce'] : {};
      var c2 = ('@coerce' in copy) ? copy['@coerce'] : {};
      delete merged['@coerce'];
      delete copy['@coerce'];
   }

   // merge contexts
   for(var key in copy)
   {
      merged[key] = copy[key];
   }
   
   // special-merge @coerce
   if(coerceExists)
   {
      for(var type in c1)
      {
         // append existing-type properties that don't already exist
         if(type in c2)
         {
            var p1 = c1[type];
            var p2 = c2[type];
            
            // normalize props in c2 to array for single-code-path iterating
            if(p2.constructor !== Array)
            {
               p2 = [p2];
            }
            
            // add unique properties from p2 to p1
            for(var i in p2)
            {
               var p = p2[i];
               if((p1.constructor !== Array && p1 !== p) ||
                  (p1.constructor === Array && p1.indexOf(p) == -1))
               {
                  if(p1.constructor === Array)
                  {
                     p1.push(p);
                  }
                  else
                  {
                     p1 = c1[type] = [p1, p];
                  }
               }
            }
         }
      }
      
      // add new types from new @coerce
      for(var type in c2)
      {
         if(!(type in c1))
         {
            c1[type] = c2[type]; 
         }
      }
      
      // ensure there are no property duplicates in @coerce
      var unique = {};
      var dups = [];
      for(var type in c1)
      {
         var p = c1[type];
         if(p.constructor === String)
         {
            p = [p];
         }
         for(var i in p)
         {
            if(!(p[i] in unique))
            {
               unique[p[i]] = true;
            }
            else if(dups.indexOf(p[i]) == -1)
            {
               dups.push(p[i]);
            }
         }
      }

      if(dups.length > 0)
      {
         throw {
            message: 'Invalid type coercion specification. More than one ' +
               'type specified for at least one property.',
            duplicates: dups
         };
      }
      
      merged['@coerce'] = c1;
   }

   return merged;
};

/**
 * Expands a term into an absolute IRI. The term may be a regular term, a
 * CURIE, a relative IRI, or an absolute IRI. In any case, the associated
 * absolute IRI will be returned.
 *
 * @param ctx the context to use.
 * @param term the term to expand.
 *
 * @return the expanded term as an absolute IRI.
 */
jsonld.expandTerm = _expandTerm;

/**
 * Compacts an IRI into a term or CURIE if it can be. IRIs will not be
 * compacted to relative IRIs if they match the given context's default
 * vocabulary.
 *
 * @param ctx the context to use.
 * @param iri the IRI to compact.
 *
 * @return the compacted IRI as a term or CURIE or the original IRI.
 */
jsonld.compactIri = function(ctx, iri)
{
   return _compactIri(ctx, iri, null);
};

/**
 * Frames JSON-LD input.
 * 
 * @param input the JSON-LD input.
 * @param frame the frame to use.
 * @param options framing options to use.
 * 
 * @return the framed output.
 */
jsonld.frame = function(input, frame, options)
{
   return new jsonld.Processor().frame(input, frame, options);
};

/**
 * Creates the JSON-LD default context.
 *
 * @return the JSON-LD default context.
 */
jsonld.createDefaultContext = _createDefaultContext;

})();
