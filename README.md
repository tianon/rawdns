# rawdns

```json
{
	"docker.": {
		"type": "containers",
		"socket": "unix:///var/run/docker.sock"
	},
	"local.": {
		"type": "forwarding",
		"nameservers": [ "192.168.1.1" ]
	},
	".": {
		"type": "forwarding",
		"nameservers": [ "8.8.8.8", "8.8.4.4" ]
	}
}
```

```console
$ docker run --rm -p 53:53/udp -v /var/run/docker.sock:/var/run/docker.sock tianon/rawdns
2014/09/23 14:46:10 listening on domain: docker.
2014/09/23 14:46:10 listening on domain: local.
2014/09/23 14:46:10 listening on domain: .
```

## wat

Since DNS is a protocol (which is a type of API), and Docker has an API, it makes a lot more sense to have DNS be a raw interface to Docker than it does to treat DNS like a database and try to synchronize the two data sources.

## why

I've eventually grown to dislike every "Docker DNS" project for one reason or another, and usually the misgivings boil down to treating DNS like a database, which reminds me of my favorite thing to say about databases: if you have the same data in two places, they are guaranteed to eventually get out of sync in some way (no matter how clever you or your code are).

## how

This is implemented by borrowing the core of SkyDNS, [`github.com/miekg/dns`](https://github.com/miekg/dns).  It's a really great, but very raw, DNS library for Go that makes it really easy to write a DNS server or client.  One of the explicit design goals of the project is "If there is stuff you should know as a DNS programmer there isn't a convenience function for it."
