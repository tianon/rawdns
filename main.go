package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/miekg/dns"
)

type Config map[string]DomainConfig // { "docker.": { ... }, ".": { ... } }

type DomainConfig struct {
	Type string `json:"type"` // "containers", "forwarding", "static"

	// "type": "containers"
	Socket string `json:"socket"` // "unix:///var/run/docker.sock"

	// "type": "forwarding"
	Nameservers []string `json:"nameservers"` // [ "8.8.8.8", "8.8.4.4" ]

	// "type": "static"
	Addrs  []string   `json:"addrs"`
	Cnames []string   `json:"cnames"`
	Txts   [][]string `json:"txts"`
	// pre-calculated/parsed
	addrs  []net.IP   // net.ParseIP(Addrs)
	cnames []string   // dns.Fqdn(Cnames)
	txts   [][]string // strings.Replace(Txts, `\`, `\\`, -1)
}

var config Config

func main() {
	log.Printf("rawdns v%s (%s/%s)\n", VERSION, runtime.GOOS, runtime.GOARCH)

	configFile := "example-config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("error: unable to read config file %s: %v\n", configFile, err)
	}
	err = json.Unmarshal(configData, &config)
	if err != nil {
		log.Fatalf("error: unable to process config file data from %s: %v\n", configFile, err)
	}

	for domain := range config {
		switch config[domain].Type {
		case "containers":
			// TODO there must be a better way to pass "domain" along without an anonymous function AND copied variable
			dCopy := domain
			dns.HandleFunc(dCopy, func(w dns.ResponseWriter, r *dns.Msg) {
				handleDockerRequest(dCopy, w, r)
			})
		case "forwarding":
			// TODO there must be a better way to pass "domain" along without an anonymous function AND copied variable
			nameservers := config[domain].Nameservers
			dns.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
				handleForwarding(nameservers, w, r)
			})
		case "static":
			cCopy := config[domain]

			cCopy.addrs = make([]net.IP, len(cCopy.Addrs))
			for i, addr := range cCopy.Addrs {
				cCopy.addrs[i] = net.ParseIP(addr)
			}

			cCopy.cnames = make([]string, len(cCopy.Cnames))
			for i, cname := range cCopy.Cnames {
				cCopy.cnames[i] = dns.Fqdn(cname)
			}

			cCopy.txts = make([][]string, len(cCopy.Txts))
			for i, txts := range cCopy.Txts {
				cCopy.txts[i] = make([]string, len(txts))
				for j, txt := range txts {
					cCopy.txts[i][j] = strings.Replace(txt, `\`, `\\`, -1)
				}
			}

			dns.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
				handleStaticRequest(cCopy, w, r)
			})
		default:
			log.Printf("error: unknown domain type on %s: %q\n", domain, config[domain].Type)
			continue
		}
		log.Printf("listening on domain: %s\n", domain)
	}

	go serve("tcp", ":53")
	go serve("udp", ":53")

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, os.Kill)
	for {
		select {
		case s := <-sig:
			log.Fatalf("fatal: signal %s received\n", s)
		}
	}
}

func serve(net, addr string) {
	server := &dns.Server{Addr: addr, Net: net, TsigSecret: nil}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to setup the %s server: %v\n", net, err)
	}
}

func dnsAppend(q dns.Question, m *dns.Msg, rr dns.RR) {
	hdr := dns.RR_Header{Name: q.Name, Class: q.Qclass, Ttl: 0}

	if rrS, ok := rr.(*dns.A); ok {
		hdr.Rrtype = dns.TypeA
		rrS.Hdr = hdr
	} else if rrS, ok := rr.(*dns.AAAA); ok {
		hdr.Rrtype = dns.TypeAAAA
		rrS.Hdr = hdr
	} else if rrS, ok := rr.(*dns.CNAME); ok {
		hdr.Rrtype = dns.TypeCNAME
		rrS.Hdr = hdr
	} else if rrS, ok := rr.(*dns.TXT); ok {
		hdr.Rrtype = dns.TypeTXT
		rrS.Hdr = hdr
	} else {
		log.Printf("error: unknown dnsAppend RR type: %+v\n", rr)
		return
	}

	if q.Qtype == dns.TypeANY || q.Qtype == rr.Header().Rrtype {
		m.Answer = append(m.Answer, rr)
	} else {
		m.Extra = append(m.Extra, rr)
	}
}

func handleDockerRequest(domain string, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	defer w.WriteMsg(m)

	domainSuffix := "." + dns.Fqdn(domain)
	for _, q := range r.Question {
		name := q.Name
		if !strings.HasSuffix(name, domainSuffix) {
			log.Printf("error: request for unknown domain %q (in %q)\n", name, domain)
			return
		}
		containerName := name[:len(name)-len(domainSuffix)]

		container, err := dockerInspectContainer(config[domain].Socket, containerName)
		if err != nil && strings.Contains(containerName, ".") {
			// we have something like "db.app", so let's try looking up a "app/db" container (linking!)
			parts := strings.Split(containerName, ".")
			var linkedContainerName string
			for i := range parts {
				linkedContainerName += "/" + parts[len(parts)-i-1]
			}
			container, err = dockerInspectContainer(config[domain].Socket, linkedContainerName)
		}
		if err != nil {
			log.Printf("error: failed to lookup container %q: %v\n", containerName, err)
			return
		}

		containerIp := container.NetworkSettings.IpAddress
		if containerIp == "" {
			log.Printf("error: container %q is IP-less\n", containerName)
			return
		}

		dnsAppend(q, m, &dns.A{A: net.ParseIP(containerIp)})

		//dnsAppend(q, m, &dns.AAAA{AAAA: net.ParseIP(container.NetworkSettings.Ipv6AddressesAsMultipleAnswerEntries)})
		// TODO IPv6 support (when Docker itself has such a thing...)
	}
}

func handleStaticRequest(config DomainConfig, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	defer w.WriteMsg(m)

	for _, q := range r.Question {
		for _, addr := range config.addrs {
			if addr.To4() != nil { // "If ip is not an IPv4 address, To4 returns nil."
				dnsAppend(q, m, &dns.A{A: addr})
			} else {
				dnsAppend(q, m, &dns.AAAA{AAAA: addr})
			}
		}

		for _, cname := range config.cnames {
			dnsAppend(q, m, &dns.CNAME{Target: cname})

			if r.RecursionDesired && len(config.Nameservers) > 0 {
				recR := &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id: dns.Id(),
					},
					Question: []dns.Question{
						{Name: cname, Qtype: q.Qtype, Qclass: q.Qclass},
					},
				}
				recM := handleForwardingRaw(config.Nameservers, recR, w.RemoteAddr())
				for _, rr := range recM.Answer {
					dnsAppend(q, m, rr)
				}
				for _, rr := range recM.Extra {
					dnsAppend(q, m, rr)
				}
			}
		}

		for _, txt := range config.txts {
			dnsAppend(q, m, &dns.TXT{Txt: txt})
		}
	}
}
