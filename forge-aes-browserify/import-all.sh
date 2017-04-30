#!/bin/sh

FORGE_PATH='../'
FORGE_TARGETS=`find ${FORGE_PATH}/js -type f | sed -E 's/.+\/(\w+).js$/\1/g' | grep -v prime.worker`

for i in ${FORGE_TARGETS};
    do node bin/import.js ${FORGE_PATH}/js/$i.js lib/$i.js;
done;

echo '\nImported files are in ./lib'
