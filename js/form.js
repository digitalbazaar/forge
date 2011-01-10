/**
 * Functions for manipulating web forms.
 * 
 * @author David I. Lehn <dlehn@digitalbazaar.com>
 * @author Dave Longley
 * @author Mike Johnson
 *
 * Copyright (c) 2011 Digital Bazaar, Inc. All rights reserved.
 */
(function($)
{
   /**
    * The form namespace.
    */
   var form = {};
   
   /**
    * Serializes a form to a JSON object.
    *
    * @param input the jquery form to serialize.
    * 
    * @return the JSON-serialized form.
    */
   form.serialize = function(input)
   {
      var output = input.serializeArray();
      
      // FIXME:
      
      return output;
   };
   
   /**
    * The forge namespace and form API.
    */
   window.forge = window.forge || {};
   window.forge.form = form;
})(jQuery);
