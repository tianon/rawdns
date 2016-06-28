#!/bin/bash
set -e

cd "$(dirname "$(readlink -f "$BASH_SOURCE")")"

docker build --pull -f Dockerfile.cross -t tianon/rawdns:cross .

rm -f rawdns*
docker run --rm tianon/rawdns:cross sh -c 'cd /go/bin && tar -c rawdns*' | tar -xv
ls -lAFh rawdns*
