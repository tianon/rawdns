package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/miekg/dns"
	"github.com/samalba/dockerclient"
)

type Config map[string]DomainConfig // { "docker.": { ... }, ".": { ... } }

type DomainConfig struct {
	Type string `json:"type"` // "containers" or "forwarding"

	// "type": "containers"
	Socket string `json:"socket"` // "unix:///var/run/docker.sock"

	// "type": "forwarding"
	Nameservers []string `json:"nameservers"` // [ "8.8.8.8:53", "8.8.4.4:53" ]
}

var config Config

func main() {
	configFile := "example-config.json" // TODO lol
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
		default:
			log.Printf("error: unknown domain type on %s: %s\n", domain, config[domain].Type)
			continue
		}
		log.Printf("listening on domain: %s\n", domain)
	}

	go serve("tcp", ":53")
	go serve("udp", ":53")

	sig := make(chan os.Signal)
	signal.Notify(sig)
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

func handleDockerRequest(domain string, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	defer w.WriteMsg(m)

	dockerHost := config[domain].Socket
	if dockerHost == "" {
		dockerHost = os.Getenv("DOCKER_HOST")
	}
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}
	docker, err := dockerclient.NewDockerClient(dockerHost, nil)
	if err != nil {
		log.Printf("error: initializing Docker client: %v\n", err)
	}

	name := r.Question[0].Name
	domainSuffix := "." + dns.Fqdn(domain)
	if !strings.HasSuffix(name, domainSuffix) {
		log.Printf("error: request for unknown domain %s (in %s)\n", name, domain)
		return
	}
	containerName := name[:len(name)-len(domainSuffix)]

	container, err := docker.InspectContainer(containerName)
	if err != nil && strings.Contains(containerName, ".") {
		// we have something like "db.app", so let's try looking up a "app/db" container (linking!)
		parts := strings.Split(containerName, ".")
		var linkedContainerName string
		for i := range parts {
			linkedContainerName += "/" + parts[len(parts)-i-1]
		}
		container, err = docker.InspectContainer(linkedContainerName)
	}
	if err != nil {
		log.Printf("error: failed to lookup container %s: %v\n", containerName, err)
		return
	}

	containerIp := container.NetworkSettings.IpAddress
	if containerIp == "" {
		log.Printf("error: container %s is IP-less\n", containerName)
		return
	}

	aRecord := new(dns.A)
	aRecord.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
	aRecord.A = net.ParseIP(containerIp)

	switch r.Question[0].Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, aRecord)

	case dns.TypeAAAA:
		m.Extra = append(m.Extra, aRecord)

		//rr := new(dns.AAAA)
		//rr.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
		//rr.AAAA = container.NetworkSettings.Ipv6AddressesAsMultipleAnswerEntries
		// TODO IPv6 support (when Docker itself has such a thing...)
	}
}
