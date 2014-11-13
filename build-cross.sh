#!/bin/bash
set -e

cd "$(dirname "$(readlink -f "$BASH_SOURCE")")"

# https://gist.github.com/tianon/9129512
cat Dockerfile.cross | perl -w -MArchive::Tar -e '
	my $tar = Archive::Tar->new;
	$tar->add_files(glob "*.go");
	{
		local $/;
		$tar->add_data("Dockerfile", <>);
	}
	print $tar->write;
' | docker build -t tianon/rawdns:cross -
rm -f rawdns*
docker run --rm tianon/rawdns:cross bash -c 'cd /go/bin && tar -c rawdns*' | tar -xv
ls -lAFh rawdns*
