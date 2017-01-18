# apt-cacher-ng

This is pretty hacky, but it works well enough.

Set up rawdns to be the default DNS for all your containers.

Run something like:

```console
$ docker run -d --name apt-cacher-ng --dns 8.8.8.8 --dns 8.8.4.4 tianon/apt-cacher-ng
```

Add the following to your `config.json` for rawdns:

```json
	"deb.debian.org.": {
		"type": "static",
		"cnames": [ "apt-cacher-ng.docker" ],
		"nameservers": [ "127.0.0.1" ]
	},
	"_http._tcp.deb.debian.org.": {
		"type": "static",
		"srvs": [ { "port": 80, "target": "apt-cacher-ng.docker." } ]
	},
	"archive.ubuntu.com.": {
		"type": "static",
		"cnames": [ "apt-cacher-ng.docker" ],
		"nameservers": [ "127.0.0.1" ]
	},
	"_http._tcp.archive.ubuntu.com.": {
		"type": "static",
		"srvs": [ { "port": 80, "target": "apt-cacher-ng.docker." } ]
	},
```

Presto: all containers magically use your machine-local apt-cacher-ng instance instead of the public mirrors.
