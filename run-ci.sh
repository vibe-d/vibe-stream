#!/bin/bash

set -e -x -o pipefail

DCVER=${DC#*-}
DC=${DC%-*}
if [ "$DC" == "ldc" ]; then DC="ldc2"; fi
DUB_FLAGS="${DUB_FLAGS:-} --compiler=$DC"


# Check for trailing whitespace"
grep -nrI --include='*.d' '\s$' . && (echo "Trailing whitespace found"; exit 1)

# test for successful release build
dub build -b release $DUB_FLAGS

# test for successful 32-bit build
if [ "$DC" == "dmd" ]; then
	dub build --arch=x86 $DUB_FLAGS
fi

dub test $DUB_FLAGS

if [ "$OS" == "macOS-13" ]; then
    dub test :tls -c openssl-1.1 $DUB_FLAGS
    DUB_FLAGS="$DUB_FLAGS --override-config vibe-stream:tls/openssl-1.1"
else
    dub test :tls $DUB_FLAGS
fi

if [ ${RUN_TEST=1} -eq 1 ]; then
    rm -f tests/loggedkeys.txt
    for ex in `cd tests && ls -1 *.d`; do
        echo "[INFO] Running test $ex"
        (cd tests && dub --temp-build --single $ex $DUB_FLAGS)
    done
    # check the keylog file was written
    test -f "tests/loggedkeys.txt"
fi
