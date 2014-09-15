package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/miekg/dns"
	"github.com/samalba/dockerclient"
)

var docker *dockerclient.DockerClient

func main() {
	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	var err error
	docker, err = dockerclient.NewDockerClient(dockerHost, nil)
	if err != nil {
		log.Fatalf("fatal: error initializing Docker client: %v\n", err)
	}

	dns.HandleFunc("docker.", handleDockerRequest)
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

func handleDockerRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	defer w.WriteMsg(m)

	name := r.Question[0].Name
	if !strings.HasSuffix(name, ".docker.") {
		log.Printf("error: request for unknown domain %s\n", name)
		return
	}
	containerName := name[:len(name)-len(".docker.")]

	container, err := docker.InspectContainer(containerName)
	if err != nil {
		log.Printf("error: failed to lookup container %s: %v\n", containerName, err)
		return
	}

	switch r.Question[0].Qtype {
	case dns.TypeA:
		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
		rr.A = net.ParseIP(container.NetworkSettings.IpAddress)
		m.Answer = append(m.Answer, rr)

	case dns.TypeAAAA:
		//rr := new(dns.AAAA)
		//rr.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
		//rr.AAAA = container.NetworkSettings.Ipv6AddressesAsMultipleAnswerEntries
		// TODO IPv6 support (when Docker itself has such a thing...)
	}
}