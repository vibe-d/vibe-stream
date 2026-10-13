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
    # The SOCKS5 test needs a real SOCKS5 server. It is installed by the CI
    # workflow; when it is missing (e.g. a local run), skip the test instead of
    # failing the whole suite.
    SOCKS5_PROXY_PORT=1080
    SOCKS5_AUTH_PORT=1081
    SOCKS5_USER=testuser
    SOCKS5_PASS=testpass

    SOCKS5_PIDS=
    if command -v microsocks >/dev/null 2>&1; then
        microsocks -p $SOCKS5_PROXY_PORT &
        SOCKS5_PIDS="$SOCKS5_PIDS $!"
        microsocks -p $SOCKS5_AUTH_PORT -u $SOCKS5_USER -P $SOCKS5_PASS &
        SOCKS5_PIDS="$SOCKS5_PIDS $!"

        # wait until a port accepts connections
        wait_port() {
            for _ in {1..50}; do
                (echo > /dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0
                sleep 0.1
            done
            return 1
        }
        wait_port $SOCKS5_PROXY_PORT || { echo "microsocks failed to start on port $SOCKS5_PROXY_PORT" >&2; exit 1; }
        wait_port $SOCKS5_AUTH_PORT || { echo "microsocks failed to start on port $SOCKS5_AUTH_PORT" >&2; exit 1; }

        export SOCKS5_PROXY_HOST=127.0.0.1
        export SOCKS5_PROXY_PORT
        export SOCKS5_AUTH_HOST=127.0.0.1
        export SOCKS5_AUTH_PORT
        export SOCKS5_USER
        export SOCKS5_PASS
    fi

    for ex in `cd tests && ls -1 *.d`; do
        if [ "$ex" == "socks5.d" ] && [ -z "$SOCKS5_PIDS" ]; then
            echo "[INFO] SKIPPING SOCKS5 test (microsocks is not installed)"
            continue
        fi
        echo "[INFO] Running test $ex"
        (cd tests && dub --temp-build --single $ex $DUB_FLAGS)
    done

    [ -n "$SOCKS5_PIDS" ] && kill $SOCKS5_PIDS 2>/dev/null
fi
