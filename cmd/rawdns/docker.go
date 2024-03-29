package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

var (
	dockerApiVersions = []string{
		// https://github.com/moby/moby/pull/46887
		"v1.41", // Docker 20.10.x

		// libnetwork doesn't provide "Networks" until at least API version 1.21
		"v1.21", // Docker 1.9.x

		// we'll fallback here, for maximum compatibility
		"v1.16", // Docker 1.4.x
	}
)

type dockerContainer struct {
	Id   string
	Name string

	NetworkSettings struct {
		Bridge     string
		MacAddress string

		Gateway     string
		IpAddress   string `json:"IPAddress"`
		IpPrefixLen int    `json:"IPPrefixLen"`

		Ip6Gateway   string `json:"IPv6Gateway"`
		Ip6Address   string `json:"GlobalIPv6Address"`
		Ip6PrefixLen int    `json:"GlobalIPv6PrefixLen"`

		// TODO Ports ?

		// see "dockerNetworkApiVersion" above
		Networks map[string]struct {
			MacAddress string

			Gateway     string
			IpAddress   string `json:"IPAddress"`
			IpPrefixLen int    `json:"IPPrefixLen"`

			Ip6Gateway   string `json:"IPv6Gateway"`
			Ip6Address   string `json:"GlobalIPv6Address"`
			Ip6PrefixLen int    `json:"GlobalIPv6PrefixLen"`
		}
	}

	Node struct {
		IP string
	}
}

func dockerGetIpList(dockerHost, containerName string, tlsConfig *tls.Config, swarmNode bool) ([]net.IP, error) {
	var (
		container *dockerContainer
		err       error
	)
	for _, apiVersion := range dockerApiVersions {
		container, err = dockerInspectContainer(dockerHost, containerName, tlsConfig, apiVersion)
		if err != nil {
			continue
		}

		if swarmNode {
			return []net.IP{net.ParseIP(container.Node.IP)}, nil
		}

		ips := []net.IP{}
		if container.NetworkSettings.IpAddress != "" {
			ips = append(ips, net.ParseIP(container.NetworkSettings.IpAddress))
		}
		if container.NetworkSettings.Ip6Address != "" {
			ips = append(ips, net.ParseIP(container.NetworkSettings.Ip6Address))
		}
		for _, network := range container.NetworkSettings.Networks {
		NextContainerIp:
			for _, ip := range []string{network.IpAddress, network.Ip6Address} {
				if ip != "" {
					parsedIp := net.ParseIP(ip)
					for _, existingIp := range ips {
						if parsedIp.Equal(existingIp) {
							// dedupe
							continue NextContainerIp
						}
						// TODO decide whether this performance hit is actually worth using a set or map structure to dedupe in nearer-constant time
					}
					ips = append(ips, net.ParseIP(ip))
				}
			}
		}
		return ips, nil
	}
	return nil, err
}

func dockerInspectContainer(dockerHost, containerName string, tlsConfig *tls.Config, apiVersion string) (*dockerContainer, error) {
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL '%s': %v", dockerHost, err)
	}
	client := httpClient(u, tlsConfig)
	req, err := http.NewRequest("GET", u.String()+"/"+apiVersion+"/containers/"+containerName+"/json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("not '200 OK': %v", resp.Status)
	}
	ret := dockerContainer{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	if err != nil {
		return nil, fmt.Errorf("failed decoding JSON response: %v", err)
	}
	return &ret, nil
}

func httpClient(u *url.URL, tlsConfig *tls.Config) *http.Client {
	transport := &http.Transport{}
	transport.DisableKeepAlives = true
	switch u.Scheme {
	case "tcp":
		if tlsConfig != nil {
			u.Scheme = "https"
			transport.TLSClientConfig = tlsConfig
		} else {
			u.Scheme = "http"
		}
	case "unix":
		path := u.Path
		transport.Dial = func(proto, addr string) (net.Conn, error) {
			return net.Dial("unix", path)
		}
		u.Scheme = "http"
		u.Host = "unix-socket"
		u.Path = ""
	}
	return &http.Client{Transport: transport}
}
