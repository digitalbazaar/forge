#!/bin/sh

FORGE_PATH='../'
FORGE_TARGETS="md cipherModes prng sha1 pbkdf2 util md5 hmac sha256 random aes cipher"

[ -d lib ] || mkdir lib

for i in ${FORGE_TARGETS};
    do
        echo "transpiling ${FORGE_PATH}js/$i.js to lib/$i.js";
        node bin/import.js ${FORGE_PATH}/js/$i.js lib/$i.js;
done;

echo "Transcoded forge libraries. run 'npm test' to see what has broken\n"
