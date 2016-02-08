#!/bin/sh -ex
mocha --debug --use_strict --full-trace --throw_deprecation --bail -t 30000 $(for i in $(ls -1 test | grep -v browser); do echo test/$i; done)
