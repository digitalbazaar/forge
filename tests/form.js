/**
 * Forge Form Tests
 *
 * @author Dave Longley
 *
 * Copyright (c) 2011 Digital Bazaar, Inc. All rights reserved.
 */
(function($) {
$(document).ready(function()
{
   // logging category
   var cat = 'forge.tests.form';
   
   // local alias
   var forge = window.forge;
   
   $('form.ajax').each(function(i, form)
   {
      // FIXME: setup form here
      forge.log.debug(cat, 'setting up');
      
      $(form).submit(function()
      {
         var f = forge.form.serialize($(this));
         forge.log.debug(cat, 'result:', f);
         $('#result').html(JSON.stringify(f));
         return false;
      });
   });
});
})(jQuery);
