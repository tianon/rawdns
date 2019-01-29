# ![rawdns](https://raw.githubusercontent.com/tianon/rawdns/master/logo-black.png)

- [Docker Hub](https://index.docker.io/u/tianon/rawdns/)
- [GitHub](https://github.com/tianon/rawdns)
- [![Build Status](https://travis-ci.org/tianon/rawdns.svg)](https://travis-ci.org/tianon/rawdns)

Save as `/etc/rawdns/config.json`:

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
$ docker run --rm -p 53:53/udp -v /var/run/docker.sock:/var/run/docker.sock -v /etc/rawdns/config.json:/etc/rawdns/config.json:ro tianon/rawdns rawdns /etc/rawdns/config.json
2014/09/23 14:46:10 listening on domain: docker.
2014/09/23 14:46:10 listening on domain: local.
2014/09/23 14:46:10 listening on domain: .
```

The most-specific domain gets the request (ie, if you have both `docker.` and `containers.docker.` and you do a lookup for `something.containers.docker`, you'll get back the IP of the container named `something`).

The default configuration only includes `docker.` going to `/var/run/docker.sock` and `.` going to `8.8.8.8`+`8.8.4.4`.

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

## swarm mode (Docker 1.12) support

`rawdns` can be used with swarm mode by creating a configuration with the `swarmmode` set to true.  The `swarmnode` option enables `rawdns` to query by service name instead of container name it will return the assigned virtual ip for the service. You can at the same time filter vip, which belong to a given network (use the `networkId` for this).

Example swarm configuration:

```json
{
    "swarm.": {
        "type": "containers",
        "socket": "unix:///var/run/docker.sock",
        "swarmmode": true,
        "networkId": "2zcqib9vlz6fa0gotr525dgcm",
        "tlsverify": true,
        "tlscacert": "/var/lib/docker/swarm/certificates/swarm-root-ca.crt",
        "tlscert": "/var/lib/docker/swarm/certificates/swarm-node.crt",
        "tlskey": "/var/lib/docker/swarm/certificates/swarm-node.key"
    },
    "example.tld.": {
        "type": "containers",
        "socket": "unix:///var/run/docker.sock",
        "swarmmode": true,
        "networkId": "2zcqib9vlz6fa0gotr525dgcm",
        "tlsverify": true,
        "tlscacert": "/var/lib/docker/swarm/certificates/swarm-root-ca.crt",
        "tlscert": "/var/lib/docker/swarm/certificates/swarm-node.crt",
        "tlskey": "/var/lib/docker/swarm/certificates/swarm-node.key"
    },
    ".": {
        "type": "forwarding",
        "nameservers": [ "8.8.8.8", "8.8.4.4" ]
    }
}
```

Example usage:

```shell
$ docker service create --name dns \
    --publish 53:53/udp \
    --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
    --mount type=bind,source=/var/lib/docker/swarm/certificates,target=/var/lib/docker/swarm/certificates \
    --mount type=bind,source=/etc/rawdns/config.json,target=/etc/rawdns/config.json \
    tianon/rawdns rawdns /etc/rawdns/config.json

2015/09/14 21:50:49 rawdns v1.2 (go1.4.2 on linux/amd64; gc)
2015/09/14 21:50:49 listening on domain: .
2015/09/14 21:50:49 listening on domain: swarm.
2015/09/14 21:50:49 listening on domain: example.tld.
```

> NOTE: You need to create the config.json on every swarm member or use `--constraint` to only run on machines with the configuration.

You can now retrieve the vip of the `dns` service (`docker service inspect dns`) and use it like this:

`docker service create --name service-using-dns --dns <vip> --dns-search example.tld myaccount/myservice`

## swarm (legacy) support

`rawdns` can be used with swarm by creating a configuration that provides the socket details using the `tcp://` scheme.  You will also need to enable `swarmnode` by setting it to true.  The `swarmnode` option enables `rawdns` to look at the `Node` section of the inspect API response for the external/host IP address.

Example swarm configuration:

```json
{
    "swarm.": {
        "type": "containers",
        "socket": "tcp://192.168.99.100:3376",
        "swarmnode": true,
        "tlsverify": true,
        "tlscacert": "/var/lib/boot2docker/ca.pem",
        "tlscert": "/var/lib/boot2docker/server.pem",
        "tlskey": "/var/lib/boot2docker/server-key.pem"
    },
    "docker.": {
        "type": "containers",
        "socket": "unix:///var/run/docker.sock"
    },
    "local.": {
        "type": "forwarding",
        "nameservers": [ "172.17.42.1" ]
    },
    ".": {
        "type": "forwarding",
        "nameservers": [ "8.8.8.8", "8.8.4.4" ]
    }
}
```

Example usage:

```shell
$ docker run --name dns --rm -it \
    -p 53:53/udp \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/lib/boot2docker:/var/lib/boot2docker \
    -v /etc/rawdns/config.json:/etc/rawdns/config.json:ro \
    tianon/rawdns rawdns /etc/rawdns/config.json

2015/09/14 21:50:49 rawdns v1.2 (go1.4.2 on linux/amd64; gc)
2015/09/14 21:50:49 listening on domain: .
2015/09/14 21:50:49 listening on domain: swarm.
2015/09/14 21:50:49 listening on domain: docker.
2015/09/14 21:50:49 listening on domain: local.

...

$ docker run -it debian:jessie bash

root@69967c3e5179:/# ping redis.swarm
PING redis.swarm (192.168.99.101): 56 data bytes
64 bytes from 192.168.99.101: icmp_seq=0 ttl=63 time=0.001 ms

root@69967c3e5179:/# ping dns.swarm
PING dns.swarm (192.168.99.100): 56 data bytes
64 bytes from 192.168.99.100: icmp_seq=0 ttl=64 time=0.030 ms

root@69967c3e5179:/# ping dns.docker
PING dns.docker (172.17.0.85): 56 data bytes
64 bytes from 172.17.0.85: icmp_seq=0 ttl=64 time=0.076 ms
```


## Development / Contributing

To build run `./build-cross.sh` (on git bash when using windows).

To create a container for testing run
`docker build -t myaccount/rawdns .`
and push with
`docker push myaccount/rawdns:latest`
