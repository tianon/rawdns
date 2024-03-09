package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"

	"github.com/docker-library/meta-scripts/om"
	"github.com/miekg/dns"
	"github.com/titanous/json5"
)

// config like { "docker.": { ... }, ".": { ... } }

type DomainConfig struct {
	Type string `json:"type"` // "containers", "forwarding", "static"

	// "type": "containers"
	Socket string `json:"socket"` // "unix:///var/run/docker.sock"

	// TLS cert/key paths are used to construct the tls.Config
	TLSVerify bool   `json:"tlsverify"`
	TLSCACert string `json:"tlscacert"`
	TLSCert   string `json:"tlscert"`
	TLSKey    string `json:"tlskey"`
	// parsed/loaded
	tlsConfig *tls.Config

	// IP address strategy
	SwarmNode bool `json:"swarmnode"`

	// "type": "forwarding"
	Nameservers []string `json:"nameservers"` // [ "8.8.8.8", "8.8.4.4" ]
	Randomize   *bool    `json:"randomize"`   // whether to randomize recursive lookups to spread upstream load (defaults to true)

	// "type": "static"
	Addrs  []string          `json:"addrs"`
	Cnames []string          `json:"cnames"`
	Ptrs   []string          `json:"ptrs"`
	Txts   [][]string        `json:"txts"`
	Srvs   []DomainConfigSrv `json:"srvs"`
	// pre-calculated/parsed
	addrs  []net.IP   // net.ParseIP(Addrs)
	cnames []string   // dns.Fqdn(Cnames)
	ptrs   []string   // dns.Fqdn(Ptrs)
	txts   [][]string // strings.Replace(Txts, `\`, `\\`, -1)
}

type DomainConfigSrv struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

func main() {
	log.Printf("rawdns v%s (%s on %s/%s; %s)\n", VERSION, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.Compiler)

	configFile := "example-config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("error: unable to read config file %s: %v\n", configFile, err)
	}

	config := om.OrderedMap[DomainConfig]{}
	if err := json.Unmarshal(configData, &config); err != nil {
		// if it isn't stock JSON, it might be json5; we'll try that (for backwards compatibility)
		var configMap map[string]DomainConfig
		if err5 := json5.Unmarshal(configData, &configMap); err5 != nil {
			log.Fatalf("error: unable to process config file data from %s: %v\n", configFile, err)
		}
		domains := make([]string, 0, len(configMap))
		for domain := range configMap {
			domains = append(domains, domain)
		}
		slices.Sort(domains)
		for _, domain := range domains {
			config.Set(domain, configMap[domain])
		}
	}

	for _, domain := range config.Keys() {
		domain := domain // https://github.com/golang/go/discussions/56010
		domainConfig := config.Get(domain)

		if domainConfig.Randomize == nil {
			randomize := true
			domainConfig.Randomize = &randomize
		}

		switch domainConfig.Type {
		case "containers":
			if domainConfig.TLSCert != "" && domainConfig.TLSKey != "" {
				var err error
				domainConfig.tlsConfig, err = loadTLSConfig(domainConfig.TLSCACert, domainConfig.TLSCert, domainConfig.TLSKey, domainConfig.TLSVerify)
				if err != nil {
					log.Fatalf("error: Unable to load tls config for %s: %s\n", domain, err)
				}
			}

			dns.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
				handleDockerRequest(domain, domainConfig, w, r)
			})

		case "forwarding":
			dns.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
				handleForwarding(domainConfig.Nameservers, *domainConfig.Randomize, w, r)
			})

		case "static":
			domainConfig.addrs = make([]net.IP, len(domainConfig.Addrs))
			for i, addr := range domainConfig.Addrs {
				domainConfig.addrs[i] = net.ParseIP(addr)
			}

			domainConfig.cnames = make([]string, len(domainConfig.Cnames))
			for i, cname := range domainConfig.Cnames {
				domainConfig.cnames[i] = dns.Fqdn(cname)
			}

			domainConfig.ptrs = make([]string, len(domainConfig.Ptrs))
			for i, ptr := range domainConfig.Ptrs {
				domainConfig.ptrs[i] = dns.Fqdn(ptr)
			}

			domainConfig.txts = make([][]string, len(domainConfig.Txts))
			for i, txts := range domainConfig.Txts {
				domainConfig.txts[i] = make([]string, len(txts))
				for j, txt := range txts {
					domainConfig.txts[i][j] = strings.Replace(txt, `\`, `\\`, -1)
				}
			}

			dns.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
				handleStaticRequest(domainConfig, w, r)
			})

		default:
			log.Fatalf("error: unknown domain type on %s: %q\n", domain, domainConfig.Type)
		}

		log.Printf("listening on domain [% -10s]: %s\n", domainConfig.Type, domain)
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
	} else if rrS, ok := rr.(*dns.PTR); ok {
		hdr.Rrtype = dns.TypePTR
		rrS.Hdr = hdr
	} else if rrS, ok := rr.(*dns.TXT); ok {
		hdr.Rrtype = dns.TypeTXT
		rrS.Hdr = hdr
	} else if rrS, ok := rr.(*dns.SRV); ok {
		hdr.Rrtype = dns.TypeSRV
		rrS.Hdr = hdr
	} else {
		log.Printf("error: unknown dnsAppend RR type: %+v\n", rr)
		return
	}

	if q.Qtype == dns.TypeANY || q.Qtype == rr.Header().Rrtype || rr.Header().Rrtype == dns.TypeCNAME {
		m.Answer = append(m.Answer, rr)
	} else {
		m.Extra = append(m.Extra, rr)
	}
}

func handleDockerRequest(domain string, domainConfig DomainConfig, w dns.ResponseWriter, r *dns.Msg) {
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

		ips, err := dockerGetIpList(domainConfig.Socket, containerName, domainConfig.tlsConfig, domainConfig.SwarmNode)
		if err != nil && strings.Contains(containerName, ".") {
			// we have something like "db.app", so let's try looking up a "app/db" container (linking!)
			parts := strings.Split(containerName, ".")
			var linkedContainerName string
			for i := range parts {
				linkedContainerName += "/" + parts[len(parts)-i-1]
			}
			ips, err = dockerGetIpList(domainConfig.Socket, linkedContainerName, domainConfig.tlsConfig, domainConfig.SwarmNode)
		}
		if err != nil {
			m.SetRcode(r, dns.RcodeNameError)
			log.Printf("error: failed to lookup container %q: %v\n", containerName, err)
			return
		}

		if len(ips) == 0 {
			log.Printf("error: container %q is IP-less\n", containerName)
			return
		}

		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				dnsAppend(q, m, &dns.A{A: ip4})
			} else {
				dnsAppend(q, m, &dns.AAAA{AAAA: ip})
			}
		}
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
				recQ := dns.Question{
					Name:   cname,
					Qtype:  q.Qtype,
					Qclass: q.Qclass,
				}
				recR := &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id: dns.Id(),
					},
					Question: []dns.Question{recQ},
				}
				recM := handleForwardingRaw(config.Nameservers, *config.Randomize, recR, w.RemoteAddr())
				for _, rr := range recM.Answer {
					dnsAppend(recQ, m, rr)
				}
				for _, rr := range recM.Extra {
					dnsAppend(recQ, m, rr)
				}
			}
		}

		for _, ptr := range config.ptrs {
			dnsAppend(q, m, &dns.PTR{Ptr: ptr})
		}

		for _, txt := range config.txts {
			dnsAppend(q, m, &dns.TXT{Txt: txt})
		}

		for _, srv := range config.Srvs {
			dnsAppend(q, m, &dns.SRV{
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   srv.Target,
			})
		}
	}
}

// Load the TLS certificates/keys and, if verify is true, the CA.
func loadTLSConfig(ca, cert, key string, verify bool) (*tls.Config, error) {
	c, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("Couldn't load X509 key pair (%s, %s): %s. Key encrypted?",
			cert, key, err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{c},
		MinVersion:   tls.VersionTLS10,
	}

	if verify {
		certPool := x509.NewCertPool()
		file, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("Couldn't read CA certificate: %s", err)
		}
		certPool.AppendCertsFromPEM(file)
		config.RootCAs = certPool
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = certPool
	} else {
		// If --tlsverify is not supplied, disable CA validation.
		config.InsecureSkipVerify = true
	}

	return config, nil
}
