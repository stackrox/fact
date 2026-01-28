#!/usr/bin/env bash

set -e

export NPROCS
NPROCS="${NPROCS:-$(nproc)}"

# shellcheck source=SCRIPTDIR/versions.sh
source builder/install/versions.sh

for f in builder/install/[0-9][0-9]-*.sh; do
    echo "=== $f ==="
    ./"$f"
    ldconfig || true  # May fail if not running as root
done
