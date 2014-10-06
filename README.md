# rawdns

- [GitHub](https://github.com/tianon/rawdns)
- [Docker Hub](https://registry.hub.docker.com/u/tianon/rawdns/)

Save as `/etc/rawdns.json`:

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

Then:

```console
$ docker run --rm -p 53:53/udp -v /var/run/docker.sock:/var/run/docker.sock /etc/rawdns.json:/etc/rawdns.json:ro tianon/rawdns rawdns /etc/rawdns.json
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

## SHOW ME

```console
$ dig @localhost dns.docker

; <<>> DiG 9.9.5 <<>> @localhost dns.docker
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18138
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;dns.docker.			IN	A

;; ANSWER SECTION:
dns.docker.		0	IN	A	172.18.0.30

;; Query time: 1 msec
;; SERVER: ::1#53(::1)
;; WHEN: Wed Sep 24 23:06:33 MDT 2014
;; MSG SIZE  rcvd: 54

$ ping dns.docker
PING dns.docker (172.18.0.30) 56(84) bytes of data.
64 bytes from 172.18.0.30: icmp_seq=1 ttl=64 time=0.025 ms
64 bytes from 172.18.0.30: icmp_seq=2 ttl=64 time=0.049 ms
64 bytes from 172.18.0.30: icmp_seq=3 ttl=64 time=0.041 ms
^C
--- dns.docker ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2001ms
rtt min/avg/max/mdev = 0.025/0.038/0.049/0.011 ms
```
