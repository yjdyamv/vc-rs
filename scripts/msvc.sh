#!/usr/bin/env bash
# Run a command inside the MSVC x64 developer environment.
# Needed to build Botan from source via the `botan-src` crate (cl.exe + nmake).
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cmd //c "$(cygpath -w "$DIR/msvc.bat") $*"
