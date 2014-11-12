// borrowed (and then modified) from https://github.com/skynetservices/skydns/blob/0301ef16a80107b84a9e25fb4afa7fb777c3f7a8/forwarding.go

// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func handleForwardingRaw(nameservers []string, req *dns.Msg, remote net.Addr) *dns.Msg {
	if len(nameservers) == 0 {
		log.Printf("no nameservers defined, can not forward\n")
		m := new(dns.Msg)
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		m.Authoritative = false     // no matter what set to false
		m.RecursionAvailable = true // and this is still true
		return m
	}

	tcp := false
	if _, ok := remote.(*net.TCPAddr); ok {
		tcp = true
	}

	var (
		r   *dns.Msg
		err error
		try int
	)
	// Use request Id for "random" nameserver selection.
	nsid := int(req.Id) % len(nameservers)
	dnsClient := &dns.Client{Net: "udp", ReadTimeout: 4 * time.Second, WriteTimeout: 4 * time.Second, SingleInflight: true}
	if tcp {
		dnsClient.Net = "tcp"
	}
Redo:
	nameserver := nameservers[nsid]
	if i := strings.Index(nameserver, ":"); i < 0 {
		nameserver += ":53"
	}
	r, _, err = dnsClient.Exchange(req, nameserver)
	if err == nil {
		r.Compress = true
		return r
	}
	// Seen an error, this can only mean, "server not reached", try again
	// but only if we have not exausted our nameservers.
	if try < len(nameservers) {
		try++
		nsid = (nsid + 1) % len(nameservers)
		goto Redo
	}

	log.Printf("failure to forward request %q\n", err)
	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	return m
}

// ServeDNSForward forwards a request to a nameservers and returns the response.
func handleForwarding(nameservers []string, w dns.ResponseWriter, req *dns.Msg) {
	w.WriteMsg(handleForwardingRaw(nameservers, req, w.RemoteAddr()))
}
