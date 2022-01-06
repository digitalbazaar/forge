/**
 * Utility for Node.js to expose crypto module.
 *
 * @author David I. Lehn
 *
 * Copyright (c) 2010-2022 Digital Bazaar, Inc.
 */

import crypto from 'crypto';

var _crypto = null;
if(!process.versions['node-webkit']) {
  _crypto = crypto;
}

export default _crypto;
