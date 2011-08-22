/**
 * Javascript implementation of JSON-LD.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2011 Digital Bazaar, Inc. All rights reserved.
 */
(function()
{

// used by Exception
var _setMembers = function(self, obj)
{
   self.stack = '';
   for(var key in obj)
   {
      self[key] = obj[key];
   }
};

// define jsonld
if(typeof(window) !== 'undefined')
{
   var jsonld = window.jsonld = window.jsonld || {};
   Exception = function(obj)
   {
      _setMembers(this, obj);
   }
}
// define node.js module
else if(typeof(module) !== 'undefined' && module.exports)
{
   var jsonld = {};
   module.exports = jsonld;
   Exception = function(obj)
   {
      _setMembers(this, obj);
      this.stack = new Error().stack;
   };
}

/*
 * Globals and helper functions.
 */
var ns =
{
   rdf: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
   xsd: 'http://www.w3.org/2001/XMLSchema#'
};

var xsd =
{
   anyType: ns.xsd + 'anyType',
   boolean: ns.xsd + 'boolean',
   double: ns.xsd + 'double',
   integer: ns.xsd + 'integer',
   anyURI: ns.xsd + 'anyURI'
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
 * Clones an object, array, or string/number. If cloning an object, the keys
 * will be sorted.
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
         rval[key] = _clone(value[key]);
      }
   }
   else if(value.constructor === Array)
   {
      rval = [];
      for(var i in value)
      {
         rval[i] = _clone(value[i]);
      }
   }
   else
   {
      rval = value;
   }
   
   return rval;
};

/**
 * Gets the keywords from a context.
 * 
 * @param ctx the context.
 * 
 * @return the keywords.
 */
var _getKeywords = function(ctx)
{
   // TODO: reduce calls to this function by caching keywords in processor
   // state
   
   var rval =
   {
      '@datatype': '@datatype',
      '@iri': '@iri',
      '@language': '@language',
      '@literal' : '@literal',
      '@subject': '@subject',
      '@type': '@type'
   };
   
   if(ctx)
   {
      // gather keyword aliases from context
      var keywords = {};
      for(var key in ctx)
      {
         if(ctx[key] in rval)
         {
            keywords[ctx[key]] = key;
         }
      }
      
      // overwrite keywords
      for(var key in keywords)
      {
         rval[key] = keywords[key];
      }
   }
   
   return rval;
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
   
   // term not found, if term is rdf type, use @type keyword
   if(rval === null && iri === ns.rdf + 'type')
   {
      rval = _getKeywords(ctx)['@type'];
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
   
   // get JSON-LD keywords
   var keywords = _getKeywords(ctx);
   
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
   else if(term === keywords['@subject'])
   {
      rval = keywords['@subject'];
   }
   // 4. The property is the special-case rdf type.
   else if(term === keywords['@type'])
   {
      rval = ns.rdf + 'type';
   }
   // 5. The property is a relative IRI, prepend the default vocab.
   else
   {
      rval = term;
      if('@vocab' in ctx)
      {
         rval = ctx['@vocab'] + rval;
         if(usedCtx !== null)
         {
            usedCtx['@vocab'] = ctx['@vocab'];
         }
      }
   }

   return rval;
};

/*
 * JSON-LD API.
 */

/**
 * Normalizes a JSON-LD object.
 *
 * @param input the JSON-LD object to normalize.
 * 
 * @return the normalized JSON-LD object.
 */
jsonld.normalize = function(input)
{
   return new Processor().normalize(input);
};

/**
 * Removes the context from a JSON-LD object, expanding it to full-form.
 *
 * @param input the JSON-LD object to remove the context from.
 * 
 * @return the context-neutral JSON-LD object.
 */
jsonld.expand = function(input)
{
   return new Processor().expand({}, null, input, false);
};

/**
 * Expands the given JSON-LD object and then compacts it using the
 * given context.
 *
 * @param ctx the new context to use.
 * @param input the input JSON-LD object.
 * 
 * @return the output JSON-LD object.
 */
jsonld.compact = function(ctx, input)
{
   var rval = null;
   
   // TODO: should context simplification be optional? (ie: remove context
   // entries that are not used in the output)

   if(input !== null)
   {
      // fully expand input
      input = jsonld.expand(input);
      
      var tmp;
      if(input.constructor === Array)
      {
         rval = [];
         tmp = input;
      }
      else
      {
         tmp = [input];
      }
      
      for(var i in tmp)
      {
         // setup output context
         var ctxOut = {};
         
         // compact
         var out = new Processor().compact(_clone(ctx), null, tmp[i], ctxOut);
         
         // add context if used
         if(Object.keys(ctxOut).length > 0)
         {
            out['@context'] = ctxOut;
         }
         
         if(rval === null)
         {
            rval = out;
         }
         else
         {
            rval.push(out);
         }
      }
   }

   return rval;
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
   var merged = _clone(ctx1);
   var copy = _clone(ctx2);

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
   return new Processor().frame(input, frame, options);
};

/**
 * Generates triples given a JSON-LD input. Each triple that is generated
 * results in a call to the given callback. The callback takes 3 parameters:
 * subject, property, and object. If the callback returns false then this
 * method will stop generating triples and return. If the callback is null,
 * then an array with triple objects containing "s", "p", "o" properties will
 * be returned.
 * 
 * The object or "o" property will be a JSON-LD formatted object.
 * 
 * @param input the JSON-LD input.
 * @param callback the triple callback.
 * 
 * @return an array of triple objects if callback is null, null otherwise.
 */
jsonld.toTriples = function(input, callback)
{
   var rval = null;
   
   // normalize input
   normalized = jsonld.normalize(input);
   
   // setup default callback
   callback = callback || null;
   if(callback === null)
   {
      rval = [];
      callback = function(s, p, o)
      {
         rval.push({'s': s, 'p': p, 'o': o});
      };
   }
   
   // generate triples
   var quit = false;
   for(var i1 in normalized)
   {
      var e = normalized[i1];
      var s = e['@subject']['@iri'];
      for(var p in e)
      {
         if(p !== '@subject')
         {
            var obj = e[p];
            if(obj.constructor !== Array)
            {
               obj = [obj];
            }
            for(var i2 in obj)
            {
               quit = (callback(s, p, obj[i2]) === false);
               if(quit)
               {
                  break;
               }
            }
            if(quit)
            {
               break;
            }
         }
      }
      if(quit)
      {
         break;
      }
   }
   
   return rval;
};

/**
 * Constructs a new JSON-LD processor.
 */
var Processor = function()
{
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
Processor.prototype.compact = function(ctx, property, value, usedCtx)
{
   var rval;
   
   // get JSON-LD keywords
   var keywords = _getKeywords(ctx);
   
   if(value === null)
   {
      // return null, but check coerce type to add to usedCtx
      rval = null;
      this.getCoerceType(ctx, property, usedCtx);
   }
   else if(value.constructor === Array)
   {
      // recursively add compacted values to array
      rval = [];
      for(var i in value)
      {
         rval.push(this.compact(ctx, property, value[i], usedCtx));
      }
   }
   // graph literal/disjoint graph
   else if(
      value.constructor === Object &&
      '@subject' in value && value['@subject'].constructor === Array)
   {
      rval = {};
      rval[keywords['@subject']] = this.compact(
         ctx, property, value['@subject'], usedCtx);
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
            // set object to compacted property, only overwrite existing
            // properties if the property actually compacted
            var p = _compactIri(ctx, key, usedCtx);
            if(p !== key || !(p in rval))
            {
               rval[p] = this.compact(ctx, key, value[key], usedCtx);
            }
         }
      }
   }
   else
   {
      // get coerce type
      var coerce = this.getCoerceType(ctx, property, usedCtx);
      
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
            throw new Exception({
               message: 'Cannot coerce type because the datatype does ' +
                  'not match.',
               type: type,
               expected: coerce
            });
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
      // no type-coercion, just change keywords/copy value
      else if(value.constructor === Object)
      {
         rval = {};
         for(var key in value)
         {
            rval[keywords[key]] = value[key];
         }
      }
      else
      {
         rval = _clone(value);
      }

      // compact IRI
      if(type === xsd.anyURI)
      {
         if(rval.constructor === Object)
         {
            rval[keywords['@iri']] = _compactIri(
               ctx, rval[keywords['@iri']], usedCtx);
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
Processor.prototype.expand = function(ctx, property, value, expandSubjects)
{
   var rval;
   
   // TODO: add data format error detection?
   
   // value is null, nothing to expand
   if(value === null)
   {
      rval = null;
   }
   // if no property is specified and the value is a string (this means the
   // value is a property itself), expand to an IRI
   else if(property === null && value.constructor === String)
   {
      rval = _expandTerm(ctx, value, null);
   }
   else if(value.constructor === Array)
   {
      // recursively add expanded values to array
      rval = [];
      for(var i in value)
      {
         rval.push(this.expand(ctx, property, value[i], expandSubjects));
      }
   }
   else if(value.constructor === Object)
   {
      // if value has a context, use it
      if('@context' in value)
      {
         ctx = jsonld.mergeContexts(ctx, value['@context']);
      }
      
      // get JSON-LD keywords
      var keywords = _getKeywords(ctx);
      
      // value has sub-properties if it doesn't define a literal or IRI value
      if(!(keywords['@literal'] in value || keywords['@iri'] in value))
      {
         // recursively handle sub-properties that aren't a sub-context
         rval = {};
         for(var key in value)
         {
            // preserve frame keywords
            if(key === '@embed' || key === '@explicit' ||
               key === '@default' || key === '@omitDefault')
            {
               _setProperty(rval, key, _clone(value[key]));
            }
            else if(key !== '@context')
            {
               // set object to expanded property
               _setProperty(
                  rval, _expandTerm(ctx, key, null),
                  this.expand(ctx, key, value[key], expandSubjects));
            }
         }
      }
      // only need to expand keywords
      else
      {
         rval = {};
         if(keywords['@iri'] in value)
         {
            rval['@iri'] = value[keywords['@iri']];
         }
         else
         {
            rval['@literal'] = value[keywords['@literal']];
            if(keywords['@language'] in value)
            {
               rval['@language'] = value[keywords['@language']];
            }
            else if(keywords['@datatype'] in value)
            {
               rval['@datatype'] = value[keywords['@datatype']];
            }
         }
      }
   }
   else
   {
      // do type coercion
      var coerce = this.getCoerceType(ctx, property, null);

      // get JSON-LD keywords
      var keywords = _getKeywords(ctx);

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
      if(coerce !== null &&
         (property !== keywords['@subject'] || expandSubjects))
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
            rval[keywords['@datatype']] = coerce;
            if(coerce === xsd.double)
            {
               // do special JSON-LD double format
               value = value.toExponential(6).replace(
                  /(e(?:\+|-))([0-9])$/, '$10$2');
            }
            rval[keywords['@literal']] = '' + value;
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

/**
 * Normalizes a JSON-LD object.
 *
 * @param input the JSON-LD object to normalize.
 * 
 * @return the normalized JSON-LD object.
 */
Processor.prototype.normalize = function(input)
{
   var rval = [];

   // TODO: validate context
   
   if(input !== null)
   {
      // create name generator state
      this.ng =
      {
         tmp: null,
         c14n: null
      };
      
      // expand input
      var expanded = this.expand({}, null, input, true);
      
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
         return _compare(a['@subject']['@iri'], b['@subject']['@iri']);
      });
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
Processor.prototype.getCoerceType = function(ctx, property, usedCtx)
{
   var rval = null;

   // get expanded property
   var p = _expandTerm(ctx, property, null);
   
   // built-in type coercion JSON-LD-isms
   if(p === '@subject' || p === ns.rdf + 'type')
   {
      rval = xsd.anyURI;
   }
   // check type coercion for property
   else if('@coerce' in ctx)
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
               
               // '@iri' is shortcut for xsd.anyURI
               if(rval === '@iri')
               {
                  rval = xsd.anyURI;
               }
               
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

var _isBlankNodeIri = function(v)
{
   return v.indexOf('_:') === 0;
};

var _isNamedBlankNode = function(v)
{
   // look for "_:" at the beginning of the subject
   return (
      v.constructor === Object && '@subject' in v &&
      '@iri' in v['@subject'] && _isBlankNodeIri(v['@subject']['@iri']));
};

var _isBlankNode = function(v)
{
   // look for no subject or named blank node
   return (
      v.constructor === Object &&
      !('@iri' in v || '@literal' in v) &&
      (!('@subject' in v) || _isNamedBlankNode(v)));
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
 * and not the other, the object with the key is less. If the key exists in
 * both objects, then the one with the lesser value is less.
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
   3.2.1. The bnode with fewer non-bnodes is first.
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
   if(input === null)
   {
      // nothing to collect
   }
   else if(input.constructor === Array)
   {
      for(var i in input)
      {
         _collectSubjects(input[i], subjects, bnodes);
      }
   }
   else if(input.constructor === Object)
   {
      if('@subject' in input)
      {
         // graph literal
         if(input['@subject'].constructor == Array)
         {
            _collectSubjects(input['@subject'], subjects, bnodes);
         }
         // named subject
         else
         {
            subjects[input['@subject']['@iri']] = input;
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
   
   if(value === null)
   {
      // drop null values
   }
   else if(value.constructor === Array)
   {
      // list of objects or a disjoint graph
      for(var i in value)
      {
         _flatten(parent, parentProperty, value[i], subjects);
      }
   }
   else if(value.constructor === Object)
   {
      // graph literal/disjoint graph
      if('@subject' in value && value['@subject'].constructor === Array)
      {
         // cannot flatten embedded graph literals
         if(parent !== null)
         {
            throw {
               message: 'Embedded graph literals cannot be flattened.'
            };
         }
         
         // top-level graph literal
         for(var key in value['@subject'])
         {
            _flatten(parent, parentProperty, value['@subject'][key], subjects);
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
         if(value['@subject']['@iri'] in subjects)
         {
            // FIXME: '@subject' might be a graph literal (as {})
            subject = subjects[value['@subject']['@iri']];
         }
         else
         {
            subject = {};
            if('@subject' in value)
            {
               // FIXME: '@subject' might be a graph literal (as {})
               subjects[value['@subject']['@iri']] = subject;
            }
         }
         flattened = subject;

         // flatten embeds
         for(var key in value)
         {
            var v = value[key];
            
            // drop null values
            if(v !== null)
            {
               if(key in subject)
               {
                  if(subject[key].constructor !== Array)
                  {
                     subject[key] = [subject[key]];
                  }
               }
               else
               {
                  subject[key] = [];
               }
               
               _flatten(subject[key], null, v, subjects);
               if(subject[key].length === 1)
               {
                  // convert subject[key] to object if it has only 1
                  subject[key] = subject[key][0];
               }
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
      // remove top-level '@subject' for subjects
      // 'http://mypredicate': {'@subject': {'@iri': 'http://mysubject'}}
      // becomes
      // 'http://mypredicate': {'@iri': 'http://mysubject'}
      if(flattened.constructor === Object && '@subject' in flattened)
      {
         flattened = flattened['@subject'];
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
 * Assigns unique names to blank nodes that are unnamed in the given input.
 * 
 * @param input the input to assign names to.
 */
Processor.prototype.nameBlankNodes = function(input)
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
      if(!('@subject' in bnode))
      {
         // generate names until one is unique
         while(ng.next() in subjects);
         bnode['@subject'] =
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
Processor.prototype.renameBlankNode = function(b, id)
{
   var old = b['@subject']['@iri'];
   
   // update bnode IRI
   b['@subject']['@iri'] = id;
   
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
Processor.prototype.canonicalizeBlankNodes = function(input)
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
      var iri = input[i]['@subject']['@iri'];
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
      var iri = bnode['@subject']['@iri'];
      if(c14n.inNamespace(iri))
      {
         // generate names until one is unique
         while(ngTmp.next() in subjects);
         this.renameBlankNode(bnode, ngTmp.current());
         iri = bnode['@subject']['@iri'];
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
      var iri = bnode['@subject']['@iri'];
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
            var iriB = b['@subject']['@iri'];
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
   this.processed = {};
   this.mapping = {};
   this.adj = {};
   this.keyStack = [{ keys: ['s1'], idx: 0 }];
   this.done = {};
   this.s = '';
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
   rval.processed = _clone(this.processed);
   rval.mapping = _clone(this.mapping);
   rval.adj = _clone(this.adj);
   rval.keyStack = _clone(this.keyStack);
   rval.done = _clone(this.done);
   rval.s = this.s;
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
 * Serializes the properties of the given bnode for its relation serialization.
 * 
 * @param b the blank node.
 * 
 * @return the serialized properties.
 */
var _serializeProperties = function(b)
{
   var rval = '';
   
   var first = true;
   for(var p in b)
   {
      if(p !== '@subject')
      {
         if(first)
         {
            first = false;
         }
         else
         {
            rval += '|';
         }
         
         // property
         rval += '<' + p + '>';
         
         // object(s)
         var objs = (b[p].constructor === Array) ? b[p] : [b[p]];
         for(var oi in objs)
         {
            var o = objs[oi];
            if(o.constructor === Object)
            {
               // iri
               if('@iri' in o)
               {
                  if(_isBlankNodeIri(o['@iri']))
                  {
                     rval += '_:';
                  }
                  else
                  {
                     rval += '<' + o['@iri'] + '>';
                  }
               }
               // literal
               else
               {
                  rval += '"' + o['@literal'] + '"';
                  
                  // datatype literal
                  if('@datatype' in o)
                  {
                     rval += '^^<' + o['@datatype'] + '>';
                  }
                  // language literal
                  else if('@language' in o)
                  {
                     rval += '@' + o['@language'];
                  }
               }
            }
            // plain literal
            else
            {
               rval += '"' + o + '"';
            }
         }
      }
   }
   
   return rval;
};

/**
 * Recursively increments the relation serialization for a mapping.
 * 
 * @param subjects the subjects in the graph.
 * @param edges the edges in the graph.
 */
MappingBuilder.prototype.serialize = function(subjects, edges)
{
   if(this.keyStack.length > 0)
   {
      // continue from top of key stack
      var next = this.keyStack.pop();
      for(; next.idx < next.keys.length; ++next.idx)
      {
         var k = next.keys[next.idx];
         if(!(k in this.adj))
         {
            this.keyStack.push(next);
            break;
         }
         
         if(k in this.done)
         {
            // mark cycle
            this.s += '_' + k;
         }
         else
         {
            // mark key as serialized
            this.done[k] = true;
            
            // serialize top-level key and its details
            var s = k;
            var adj = this.adj[k];
            var iri = adj.i;
            if(iri in subjects)
            {
               var b = subjects[iri];
               
               // serialize properties
               s += '[' + _serializeProperties(b) + ']';
               
               // serialize references
               var first = true;
               s += '[';
               var refs = edges.refs[iri].all;
               for(var r in refs)
               {
                  if(first)
                  {
                     first = false;
                  }
                  else
                  {
                     s += '|';
                  }
                  s += '<' + refs[r].p + '>';
                  s += _isBlankNodeIri(refs[r].s) ?
                     '_:' : ('<' + refs[r].s + '>');
               }
               s += ']';
            }
            
            // serialize adjacent node keys
            s += adj.k.join('');
            this.s += s;
            this.keyStack.push({ keys: adj.k, idx: 0 });
            this.serialize(subjects, edges);
         }
      }
   }
};

/**
 * Marks a relation serialization as dirty if necessary.
 * 
 * @param iri the IRI of the bnode to check.
 * @param changed the old IRI of the bnode that changed.
 * @param dir the direction to check ('props' or 'refs').
 */
Processor.prototype.markSerializationDirty = function(iri, changed, dir)
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
 * Recursively serializes adjacent bnode combinations for a bnode.
 * 
 * @param s the serialization to update.
 * @param iri the IRI of the bnode being serialized.
 * @param siri the serialization name for the bnode IRI.
 * @param mb the MappingBuilder to use.
 * @param dir the edge direction to use ('props' or 'refs').
 * @param mapped all of the already-mapped adjacent bnodes.
 * @param notMapped all of the not-yet mapped adjacent bnodes.
 */
Processor.prototype.serializeCombos = function(
   s, iri, siri, mb, dir, mapped, notMapped)
{
   // handle recursion
   if(notMapped.length > 0)
   {
      // copy mapped nodes
      mapped = _clone(mapped);
      
      // map first bnode in list
      mapped[mb.mapNode(notMapped[0].s)] = notMapped[0].s;
      
      // recurse into remaining possible combinations
      var original = mb.copy();
      notMapped = notMapped.slice(1);
      var rotations = Math.max(1, notMapped.length);
      for(var r = 0; r < rotations; ++r)
      {
         var m = (r === 0) ? mb : original.copy();
         this.serializeCombos(s, iri, siri, m, dir, mapped, notMapped);
         
         // rotate not-mapped for next combination
         _rotate(notMapped);
      }
   }
   // no more adjacent bnodes to map, update serialization
   else
   {
      var keys = Object.keys(mapped).sort();
      mb.adj[siri] = { i: iri, k: keys, m: mapped };
      mb.serialize(this.subjects, this.edges);
      
      // optimize away mappings that are already too large
      if(s[dir] === null || _compareSerializations(mb.s, s[dir].s) <= 0)
      {
         // recurse into adjacent values
         for(var i in keys)
         {
            var k = keys[i];
            this.serializeBlankNode(s, mapped[k], mb, dir);
         }
         
         // update least serialization if new one has been found
         mb.serialize(this.subjects, this.edges);
         if(s[dir] === null ||
            (_compareSerializations(mb.s, s[dir].s) <= 0 &&
            mb.s.length >= s[dir].s.length))
         {
            s[dir] = { s: mb.s, m: mb.mapping };
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
Processor.prototype.serializeBlankNode = function(s, iri, mb, dir)
{
   // only do mapping if iri not already processed
   if(!(iri in mb.processed))
   {
      // iri now processed
      mb.processed[iri] = true;
      var siri = mb.mapNode(iri);
      
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
      
      /*
      // TODO: sort notMapped using ShallowCompare
      var self = this;
      notMapped.sort(function(a, b)
      {
         var rval = self.shallowCompareBlankNodes(
            self.subjects[a.s], self.subjects[b.s]);
         return rval;
      });
      
      var same = false;
      var prev = null;
      for(var i in notMapped)
      {
         var curr = this.subjects[notMapped[i].s];
         if(prev !== null)
         {
            if(this.shallowCompareBlankNodes(prev, curr) === 0)
            {
               same = true;
            }
            else
            {
               if(!same)
               {
                  mapped[mb.mapNode(prev['@subject'])] = prev['@subject'];
                  delete notMapped[i - 1];
               }
               if(i === notMapped.length - 1)
               {
                  mapped[mb.mapNode(curr['@subject'])];
                  delete notMapped[i];
               }
               same = false;
            }
         }
         prev = curr;
      }*/
      
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
         this.serializeCombos(s, iri, siri, m, dir, mapped, notMapped);         
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
Processor.prototype.deepCompareBlankNodes = function(a, b)
{
   var rval = 0;
   
   // compare IRIs
   var iriA = a['@subject']['@iri'];
   var iriB = b['@subject']['@iri'];
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
Processor.prototype.shallowCompareBlankNodes = function(a, b)
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
      var edgesA = this.edges.refs[a['@subject']['@iri']].all;
      var edgesB = this.edges.refs[b['@subject']['@iri']].all;
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
Processor.prototype.compareEdges = function(a, b)
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
Processor.prototype.collectEdges = function()
{
   var refs = this.edges.refs;
   var props = this.edges.props;
   
   // collect all references and properties
   for(var iri in this.subjects)
   {
      var subject = this.subjects[iri];
      for(var key in subject)
      {
         if(key !== '@subject')
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
   var type = ns.rdf + 'type';
   if(type in frame &&
      input.constructor === Object && '@subject' in input && type in input)
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
   var type = ns.rdf + 'type';
   if(!(type in frame))
   {
      // get frame properties that must exist on input
      var props = Object.keys(frame).filter(function(e)
      {
         // filter non-keywords
         return e.indexOf('@') !== 0;
      });
      if(props.length === 0)
      {
         // input always matches if there are no properties
         rval = true;
      }
      // input must be a subject with all the given properties
      else if(input.constructor === Object && '@subject' in input)
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
      if(frames.length === 0)
      {
         frames.push({});
      }
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
            message: 'Invalid JSON-LD frame. ' +
               'Frame must be an object or an array.'
         };
      }
      
      // create array of values for each frame
      values[i] = [];
      for(var n = 0; n < input.length && limit !== 0; ++n)
      {
         // add input to list if it matches frame specific type or duck-type
         var next = input[n];
         if(_isType(next, frame) || _isDuckType(next, frame))
         {
            values[i].push(next);
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
            if(value.constructor === Object && '@subject' in value)
            {
               value = value['@subject'];
            }
         }
         else if(
            value.constructor === Object &&
            '@subject' in value && value['@subject']['@iri'] in embeds)
         {
            // TODO: possibly support multiple embeds in the future ... and
            // instead only prevent cycles?
            throw {
               message: 'More than one embed of the same subject is not ' +
                  'supported.',
               subject: value['@subject']['@iri']
            };
         }
         // if value is a subject, do embedding and subframing
         else if(value.constructor === Object && '@subject' in value)
         {
            embeds[value['@subject']['@iri']] = true;
            
            // if explicit is on, remove keys from value that aren't in frame
            var explicitOn = ('@explicit' in frame) ?
               frame['@explicit'] : options.defaults.explicitOn;
            if(explicitOn)
            {
               for(key in value)
               {
                  // do not remove subject or any key in the frame
                  if(key !== '@subject' && !(key in frame))
                  {
                     delete value[key];
                  }
               }
            }
            
            // iterate over frame keys to do subframing
            for(key in frame)
            {
               // skip keywords and type query
               if(key.indexOf('@') !== 0 && key !== ns.rdf + 'type')
               {
                  var f = frame[key];
                  if(key in value)
                  {
                     // build input and do recursion
                     var v = value[key];
                     input = (v.constructor === Array) ? v : [v];
                     for(var n in input)
                     {
                        // replace reference to subject w/subject
                        if(input[n].constructor === Object &&
                           '@iri' in input[n] && input[n]['@iri'] in subjects)
                        {
                           input[n] = subjects[input[n]['@iri']];
                        }
                     }
                     value[key] = _frame(subjects, input, f, embeds, options);
                  }
                  else
                  {
                     // add empty array/null property to value
                     value[key] = (f.constructor === Array) ? [] : null;
                  }
                  
                  // handle setting default value
                  if(value[key] === null)
                  {
                     // use first subframe if frame is an array
                     if(f.constructor === Array)
                     {
                        f = (f.length > 0) ? f[0] : {};
                     }
                     
                     // determine if omit default is on
                     var omitOn = ('@omitDefault' in f) ?
                        f['@omitDefault'] : options.defaults.omitDefaultOn;
                     if(omitOn)
                     {
                        delete value[key];
                     }
                     else if('@default' in f)
                     {
                        value[key] = f['@default'];
                     }
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
Processor.prototype.frame = function(input, frame, options)
{
   var rval;
   
   // normalize input
   input = jsonld.normalize(input);
   
   // save frame context
   var ctx = null;
   if('@context' in frame)
   {
      ctx = _clone(frame['@context']);
   }
   
   // remove context from frame
   frame = jsonld.expand(frame);
   
   // create framing options
   // TODO: merge in options from function parameter
   options =
   {
      defaults:
      {
         embedOn: true,
         explicitOn: false,
         omitDefaultOn: false
      }
   };
   
   // build map of all subjects
   var subjects = {};
   for(var i in input)
   {
      subjects[input[i]['@subject']['@iri']] = input[i];
   }
   
   // frame input
   rval = _frame(subjects, input, frame, {}, options);
   
   // apply context
   if(ctx !== null && rval !== null)
   {
      rval = jsonld.compact(ctx, rval);
   }
   
   return rval;
};

})();
