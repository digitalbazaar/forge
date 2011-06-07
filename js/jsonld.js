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
}
// define node.js module
else if(typeof(module) !== 'undefined' && module.exports)
{
   var forge = {};
   module.exports = forge.jsonld = {};
}

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
      a: jsonld.ns.rdf + 'type',
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
      }
   };
   return ctx;
};

/**
 * Compacts an IRI into a term or CURIE it can be. IRIs will not be
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
   
   // check the context for a term or prefix that could shorten the IRI
   for(var key in ctx)
   {
      // skip special context keys (start with '@')
      if(key.length > 0 && key.indexOf('@') !== 0)
      {
         // see if IRI begins with the next IRI from the context
         var ctxIri = ctx[key];
         var idx = iri.indexOf(ctxIri);
         if(idx === 0)
         {
            // compact to a CURIE
            if(iri.length > ctxIri.length)
            {
               // add 2 to make room for null-terminator and colon
               rval = key + ':' + iri.substr(idx + ctxIri.length);
               if(usedCtx)
               {
                  usedCtx[name] = ctxIri;
               }
               break;
            }
            // compact to a term
            else if(idx.length == ctxIri.length)
            {
               rval = name;
               if(usedCtx)
               {
                  usedCtx[name] = ctxIri;
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
         if(usedCtx)
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
      if(usedCtx)
      {
         usedCtx[term] = rval;
      }
   }
   // 3. The property is the special-case '@'
   else if(term === "@")
   {
      rval = "@";
   }
   // 4. The property is a relative IRI, prepend the default vocab.
   else
   {
      rval = ctx['@vocab'] + term;
      if(usedCtx)
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
 * Clones a value that is an array or an object. Deep clone is not performed.
 * 
 * @param value the value to clone.
 * 
 * @return the cloned value.
 */
var _clone = function(value)
{
   var rval = {};
   for(var key in value)
   {
      rval[key] = value[key];
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
   var p = _expandTerm(ctx, property);

   // built-in type coercion JSON-LD-isms
   if(p === '@' || p === jsonld.ns.rdf + 'type')
   {
      rval = xsd.anyURI;
   }
   // check type coercion for property
   else
   {
      // force compacted property
      p = _compactIri(ctx, p);
      
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
               if(usedCtx)
               {
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
   
   if(value.constructor === Array)
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
      '@' in value && value['@'].constructor === Array)
   {
      rval = {};
      rval['@'] = _compact(ctx, property, value['@'], usedCtx);
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
      rval = _expandTerm(ctx, value);
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
            if(key !== '@context')
            {
               // set object to expanded property
               _setProperty(
                  rval, _expandTerm(ctx, key),
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
      var coerce = _getCoerceType(ctx, property);

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

      // only expand subjects if requested
      if(coerce !== null && (property !== '@' || expandSubjects))
      {
         rval = {};
         
         // expand IRI
         if(coerce === xsd.anyURI)
         {
            rval['@iri'] = _expandTerm(ctx, value);
         }
         // other datatype
         else
         {
            rval['@literal'] = value;
            rval['@datatype'] = coerce;
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

var _isNamedBlankNode = function(v)
{
   // look for "_:" at the beginning of the subject
   return (
      v.constructor === Object && '@' in v &&
      '@iri' in v['@'] &&
      v['@']['@iri'].indexOf('_:') === 0);
};

var _isBlankNode = function(v)
{
   // look for no subject or named blank node
   return (
      v.constructor === Object &&
      !('@iri' in v || '@literal' in v) &&
      (!('@' in v) || _isNamedBlankNode(v)));
};

/**
 * Flattens the given value into a map of unique subjects, where
 * the only embeds are unnamed blank nodes. If any named blank nodes are
 * encountered, an exception will be raised.
 *
 * @param parent the value's parent, NULL for none.
 * @param parentProperty the property relating the value to the parent.
 * @param value the value to flatten.
 * @param subjects the map of subjects to write to.
 * @param out the top-level array for flattened values.
 */
var _flatten = function(parent, parentProperty, value, subjects, out)
{
   var flattened = null;
   
   if(value.constructor === Array)
   {
      for(var i in value)
      {
         _flatten(parent, parentProperty, value[i], subjects, out);
      }
   }
   else if(value.constructor === Object)
   {
      // graph literal/disjoint graph
      if('@' in value && value['@'].constructor === Array)
      {
         // cannot flatten embedded graph literals
         if(parent !== null)
         {
            throw {
               message: 'Embedded graph literals cannot be flattened.'
            };
         }
         
         // top-level graph literal
         for(var key in value['@'])
         {
            _flatten(parent, parentProperty, value['@'][key], subjects, out);
         }
      }
      // named blank node
      else if(_isNamedBlankNode(value))
      {
         // FIXME: permit flattening of named blank nodes
         throw {
            message: 'Could not flatten JSON-LD. It contains a named ' +
               'blank node.'
         };
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
         if('@' in value && value['@'] in subjects)
         {
            // FIXME: '@' might be a graph literal (as {})
            subject = subjects[value['@']['@iri']];
         }
         else
         {
            subject = {};
            if('@' in value)
            {
               // FIXME: '@' might be a graph literal (as {})
               subjects[value['@']['@iri']] = subject;
            }
         }
         flattened = subject;

         // flatten embeds
         for(var key in value)
         {
            if(value[key].constructor === Array)
            {
               subject[key] = [];
               _flatten(subject[key], null, value[key], subjects, out);
            }
            else
            {
               _flatten(subject, key, value[key], subjects, out);
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
   if(flattened !== null)
   {
      // if the flattened value is an unnamed blank node, add it to the
      // top-level output
      if(parent === null && _isBlankNode(flattened))
      {
         parent = out;
      }

      if(parent !== null)
      {
         // remove top-level '@' for subjects
         // 'http://mypredicate': {'@': {'@iri': 'http://mysubject'}} becomes
         // 'http://mypredicate': {'@iri': 'http://mysubject'}
         if(flattened.constructor === Object && '@' in flattened)
         {
            flattened = flattened['@'];
         }

         if(parent.constructor === Array)
         {
            parent.push(flattened);
         }
         else
         {
            parent[parentProperty] = flattened;
         }
      }
   }
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
   var rval = [];

   // TODO: validate context

   if(input !== null)
   {
      // get default context
      var ctx = _createDefaultContext();

      // expand input
      var expanded = _expand(ctx, null, input, true);
      
      // flatten
      var subjects = {};
      _flatten(null, null, expanded, subjects, rval);

      // append unique subjects to array of sorted triples
      for(var key in subjects)
      {
         rval.push(subjects[key]);
      }

      // sort output
      rval.sort(function(a, b)
      {
         var rval = 0;
         
         // FIXME: after canonical bnode naming is implemented, all entries
         // will have '@'
         if('@' in a && !('@' in b))
         {
            rval = 1;
         }
         else if('@' in b && !('@' in a))
         {
            rval = -1;
         }
         else if(a['@']['@iri'] < b['@']['@iri'])
         {
            rval = -1;
         }
         else if(a['@']['@iri'] > b['@']['@iri'])
         {
            rval = 1;
         }
         
         return rval;
      });
   }

   return rval;
};

/**
 * Removes the context from a JSON-LD object.
 *
 * @param input the JSON-LD object to remove the context from.
 * 
 * @return the context-neutral JSON-LD object.
 */
jsonld.removeContext = function(input)
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
   if(Object.keys(ctxOut).length() > 0)
   {
      // add copy of context to every entry in output array
      if(rval.constructor === Array)
      {
         for(var i in rval)
         {
            rval[i]['@context'] = _cloneContext(ctxOut);
         }
      }
   }
   else
   {
      rval['@context'] = ctxOut;
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
jsonld.changeContext = function(ctx, input)
{
   // remove context and then add new one
   return addContext(ctx, removeContext(input));
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
            }
         }
      }
   }

   // @coerce must be specially-merged, remove from context
   if('@coerce' in merged || '@coerce' in copy)
   {
      var c1 = ('@coerce' in merged) ? merged['@coerce'] : {};
      var c2 = ('@coerce' in copy) ? copy['@coerce'] : {};
      delete merged['@coerce'];
      delete copy['@coerce'];

      // merge contexts
      for(var key in copy)
      {
         merged[key] = copy[key];
      }
      
      // special-merge @coerce
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
 * Compacts an IRI into a term or CURIE it can be. IRIs will not be
 * compacted to relative IRIs if they match the given context's default
 * vocabulary.
 *
 * @param ctx the context to use.
 * @param iri the IRI to compact.
 *
 * @return the compacted IRI as a term or CURIE or the original IRI.
 */
jsonld.compactIri = _compactIri;

})();
