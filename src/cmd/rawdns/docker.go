package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

type dockerContainer struct {
	Id   string
	Name string

	NetworkSettings struct {
		Bridge      string
		Gateway     string
		IpAddress   string `json:"IPAddress"`
		IpPrefixLen int    `json:"IPPrefixLen"`
		MacAddress  string
		// TODO Ports ?
	}

	Node struct {
		IP string
	}
}

func dockerInspectContainer(dockerHost, containerName string, tlsConfig *tls.Config) (*dockerContainer, error) {
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL '%s': %v", dockerHost, err)
	}
	client := httpClient(u, tlsConfig)
	req, err := http.NewRequest("GET", u.String()+"/v1.16/containers/"+containerName+"/json", nil)
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
