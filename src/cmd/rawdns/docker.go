package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"log"
	"strings"
	"regexp"
	"strconv"
)

var (
	dockerApiVersions = []string{
		// swarm mode was added in 1.24.
		"v1.24",

		// libnetwork doesn't provide "Networks" until at least API version 1.21
		"v1.21",

		// we'll fallback here, for maximum compatibility
		"v1.16",
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

type dockerService struct {
	ID      string
	Version struct {
		Index int
	}
	CreatedAt string
	UpdatedAt string
	Spec      struct {
		Name string
	}
	Endpoint struct {
		Spec      struct {
			Mode string         // vip or dnsrr
		}
		Ports      []Port
		VirtualIps []struct {
			NetworkID string
			Addr      string
		}
	}
}
type Port struct {
	Protocol      string
	TargetPort    uint16
	PublishedPort uint16
	PublishMode   string    // ingress or host
}

type dockerTasks struct {
	ID      string
	Version struct {
		Index int
	}
	CreatedAt string
	UpdatedAt string
	ServiceID string
	Slot      int
	NodeID    string
	Status struct {
		PortStatus struct {
			Ports  []Port       // ports in case of PublishMode: "host"
		}
	}
	NetworksAttachments []struct {
		Network struct {
			ID string
			Spec struct {
				Name string
				Ingress bool
			}
		}
		Addresses []string
	}
}
type dockerNode struct {
	ID       string
	Spec struct {
		Name     string
	}
	Description struct {
		Hostname string
	}
	Status struct {
		Addr     string
	}
}
type dockerTasksFilter struct {
	TaskId        string
	Slot          int
	NetworkName   string
	NetworkOrId   string
	DiscoverTasks bool
}
type Network struct {
	Id      string
	Name    string
	Ingress bool
	Peers   []struct {
		Name  string
		IP    string
	}
}
type dockerHosts struct {
	Name        string
	Ip          net.IP
	Ports       []uint16
	Slot        int
	TasksID     string
	Network     Network
}
func dockerGetIpList(dockerHost, domainPrefixOrContainerName string, tlsConfig *tls.Config, swarmNode bool, swarmMode bool, networkID string, serviceDiscovery bool) ([]dockerHosts, error) {
	var (
		container *dockerContainer
		service   *dockerService
		tasks     *[]dockerTasks
		err       error
	)

	for _, apiVersion := range dockerApiVersions {
		if swarmMode {
			//log.Printf("[debug] dockerGetIpList: service FQDN or hostname - %q\n", domainPrefixOrContainerName)

			discoverTasks := false
			if serviceDiscovery {
				discoverTasks = true
			}
			var filter *dockerTasksFilter
			service, filter, err = dockerDiscoverService(dockerHost, domainPrefixOrContainerName, tlsConfig, apiVersion)
			if err != nil {
				continue
			}
			if discoverTasks && !filter.DiscoverTasks {
				filter.DiscoverTasks = discoverTasks
			}
			/* for endpoint_mode: dnsrr - we have no VIP or other IPs for service, thus force service discovery to get task's IPs
			 * for endpoint_mode: vip - we have VIPs for the service, no need to return IPs for directly bound to nodes ports
			 */
			if service.Endpoint.Spec.Mode == "dnsrr" {
				filter.DiscoverTasks = true
			}

			if filter.DiscoverTasks {
				tasks, err = dockerInspectTasks(dockerHost, service.Spec.Name, tlsConfig, apiVersion)
				if err != nil {
					//log.Printf("[debug] error: %v\n", err)
					continue
				}
				targetPorts := []uint16{}
				for _, port := range service.Endpoint.Ports {
					targetPorts = append(targetPorts, port.TargetPort)
				}
				publishedPorts := []uint16{}
				for _, port := range service.Endpoint.Ports {
					publishedPorts = append(publishedPorts, port.PublishedPort)
				}
				hosts := []dockerHosts{}
				if filter.Slot > 0 || filter.NetworkOrId != "" {
					//log.Printf("[debug] dockerGetIpList: filter for Slot=%v or NetworkOrId=%q or taskId=%q\n", filter.Slot, filter.NetworkOrId, filter.TaskId)
				}
				for _, task := range *tasks {
					//log.Printf("[debug] dockerGetIpList: task %+v\n", task)
					if filter.Slot > 0 && filter.Slot != task.Slot {
						continue
					}
					for _, netAttachments := range task.NetworksAttachments {
						if (networkID != "" && netAttachments.Network.ID != networkID) /*|| netAttachments.Network.Spec.Ingress*/ {
							continue
						}
						taskNetworkName :=  strings.Replace(netAttachments.Network.Spec.Name, "_", "-", -1)
						if filter.NetworkOrId != "" && filter.NetworkOrId != taskNetworkName && filter.NetworkOrId != netAttachments.Network.Spec.Name && filter.NetworkOrId != task.ID {
							continue
						}
						if filter.TaskId != "" && filter.TaskId != task.ID {
							continue
						}
						for _, addr := range netAttachments.Addresses {

							ip, _, err := net.ParseCIDR(addr)
							if err != nil {
								return nil, err
							}
							// to swarm external access we need to convert swarm local IP to a node (peer) IP
							if netAttachments.Network.Spec.Ingress {
								ingress, err := dockerInspectNetwork(dockerHost, netAttachments.Network.ID, tlsConfig, apiVersion)
								if err != nil {
									log.Printf("error: %v\n", err)
								} else {
									if ingress.Peers != nil {
										for _, peer := range ingress.Peers {
											pIp := net.ParseIP(peer.IP)
											if pIp != nil {
												ip = pIp
											}
										}
									}
								}
							}
							ports := targetPorts
							if netAttachments.Network.Spec.Ingress {
								ports = publishedPorts
							}
							hosts = append(hosts, dockerHosts{
									Name:        strings.Replace(service.Spec.Name, "_", "-", -1),
									Ip:          ip,
									Ports:       ports,
									Slot:        task.Slot,
									TasksID:     task.ID,
									Network:     Network{
													Id:      netAttachments.Network.ID,
													Name:    taskNetworkName,
													Ingress: netAttachments.Network.Spec.Ingress,
									},
							})
						}
					}
					// PublishedPort's with PublishMode: "host"
					// in the case in addition to the ingress endpoint might be exist directly bound ports to a node host ports
					if len(task.Status.PortStatus.Ports) > 0 {
						if filter.NetworkOrId != "" && (filter.NetworkOrId != "bridge" && filter.NetworkOrId != "ingress") {
							continue
						}
						ports := []uint16{}
						for _, port := range task.Status.PortStatus.Ports {
							// host network, peer IP
							ports = append(ports, port.PublishedPort)
						}

						node, err := dockerInspectNode(dockerHost, task.NodeID, tlsConfig, apiVersion)
						if err != nil {
							log.Printf("error: %v\n", err)
						} else {
							//log.Printf("[debug] dockerGetIpList: node %+v\n", node)
							nodeIp := net.ParseIP(node.Status.Addr)
							if nodeIp != nil {
								hosts = append(hosts, dockerHosts{
										Name:        strings.Replace(service.Spec.Name, "_", "-", -1),
										Ip:          nodeIp,
										Ports:       ports,
										Slot:        task.Slot,
										TasksID:     task.ID,
										Network:     Network{
														Name:    "bridge",
										},
								})
							}
						}
					}
				}
				return hosts, nil
			} else {

				nets, err := dockerInspectNetworks(dockerHost, tlsConfig, apiVersion)
				if err != nil {
					log.Printf("error: %v\n", err)
				}

				hosts := []dockerHosts{}
				for _, vip := range service.Endpoint.VirtualIps {
					if networkID != "" && vip.NetworkID != networkID {
						continue
					}
					normNetName := ""
					ingress := false
					if nets != nil && len(*nets) > 0 {
						if net, ok := (*nets)[vip.NetworkID]; ok {
							normNetName =  strings.Replace(net.Name, "_", "-", -1)
							ingress = net.Ingress

							if filter.NetworkOrId != "" && normNetName != filter.NetworkOrId && net.Name != filter.NetworkOrId && net.Id != filter.NetworkOrId {
								//log.Printf("[debug] dockerGetIpList: filtered out network %q: %q (%q)\n", net.Id, net.Name, normNetName)
								continue
							}
						}
					}

					ip, _, err := net.ParseCIDR(vip.Addr)
					if err != nil {
						return nil, err
					}

					// to swarm external access we need to convert swarm local IP to a node (peer) IP
					if ingress {
						ingressNet, err := dockerInspectNetwork(dockerHost, vip.NetworkID, tlsConfig, apiVersion)
						if err != nil {
							log.Printf("error: %v\n", err)
						} else {
							if ingressNet.Peers != nil {
								for _, peer := range ingressNet.Peers {
									pIp := net.ParseIP(peer.IP)
									if pIp != nil {
										ip = pIp
									}
								}
							}
						}
					}

					hosts = append(hosts, dockerHosts{
							Name: domainPrefixOrContainerName,
							Ip: ip,
							Network: Network{vip.NetworkID, normNetName, ingress, nil},
					})
				}
				/* for PublishMode: "host"
				 * and endpoint_mode: vip - we have VIPs for the service, no need to return IPs for directly bound to nodes ports
				 * for endpoint_mode: dnsrr - service discovery is forced
				 */

				return hosts, nil
			}
		}
		container, err = dockerInspectContainer(dockerHost, domainPrefixOrContainerName, tlsConfig, apiVersion)
		if err != nil {
			continue
		}

		if swarmNode {
			return []dockerHosts{dockerHosts{Ip: net.ParseIP(container.Node.IP)}}, nil
		}

		hosts := []dockerHosts{}
		if container.NetworkSettings.IpAddress != "" {
			hosts = append(hosts, dockerHosts{Ip: net.ParseIP(container.NetworkSettings.IpAddress)})
		}
		if container.NetworkSettings.Ip6Address != "" {
			hosts = append(hosts, dockerHosts{Ip: net.ParseIP(container.NetworkSettings.Ip6Address)})
		}
		for _, network := range container.NetworkSettings.Networks {
		NextContainerIp:
			for _, ip := range []string{network.IpAddress, network.Ip6Address} {
				if ip != "" {
					parsedIp := net.ParseIP(ip)
					for _, hosts := range hosts {
						if parsedIp.Equal(hosts.Ip) {
							// dedupe
							continue NextContainerIp
						}
						// TODO decide whether this performance hit is actually worth using a set or map structure to dedupe in nearer-constant time
					}
					hosts = append(hosts, dockerHosts{Ip: net.ParseIP(ip)})
				}
			}
		}
		return hosts, nil
	}
	return nil, err
}
func dockerDiscoverService(dockerHost, serviceName string, tlsConfig *tls.Config, apiVersion string) (*dockerService, *dockerTasksFilter, error) {
	var (
		service   *dockerService
		err       error
	)
			res := dockerTasksFilter{}
			// Mimic Docker DNS behaviour: tasks.servicename[.domain]
			if strings.HasPrefix(serviceName, "tasks.") {
				serviceName = serviceName[len("tasks."):]
				res.DiscoverTasks = true
			}

			service, err = dockerInspectService(dockerHost, serviceName, tlsConfig, apiVersion)
			if err != nil {
				// Mightbe this is a FQDN query, extract servicename from FQDN
				// let's try looking up for a "service[.taskSlot][.taskId][.network]" template
				if strings.Contains(serviceName, ".") {
					fqdnParts := strings.Split(serviceName, ".")
					serviceName = fqdnParts[0]

					// extrtact taskSlot and taskId or network if exist.
					if len(fqdnParts) > 1 {
						if slot, err := strconv.Atoi(fqdnParts[1]); err == nil {
							res.Slot = slot
							if len(fqdnParts) > 2 {
								res.NetworkOrId = fqdnParts[len(fqdnParts)-1]
							}
							res.DiscoverTasks = true
						} else {
							res.NetworkOrId = fqdnParts[len(fqdnParts)-1]
							if len(fqdnParts) > 2 {
								res.TaskId = fqdnParts[len(fqdnParts)-2]
								res.DiscoverTasks = true
							}
						}
					}
					service, err = dockerInspectService(dockerHost, serviceName, tlsConfig, apiVersion)
				}
				if service == nil {
					// Mightbe taskId separated by dash instead of dot
					// let's extract servicename and slot from "servicename-taskSlot" template
					re, err := regexp.Compile(`([^.]+)(?:[-]+(\d+))`);
					if err != nil {
						return nil, nil, err
					}
					if matches := re.FindStringSubmatch(serviceName); len(matches) > 1 {
						serviceName = matches[1]
						//log.Printf("[debug] dockerDiscoverService: matches %v\n", matches)
						if len(matches) > 2 {
							if slot, err := strconv.Atoi(matches[2]); err == nil {
								res.Slot = slot
								res.DiscoverTasks = true
							}
						}
						service, err = dockerInspectService(dockerHost, serviceName, tlsConfig, apiVersion)
					}
				}
				if service == nil {
					service, err = dockerDiscoverStackedService(dockerHost, serviceName, tlsConfig, apiVersion)
				}
				if service == nil {
					return nil, nil, err
				}
			}
	return service, &res, nil
}
func dockerDiscoverStackedService(dockerHost, serviceName string, tlsConfig *tls.Config, apiVersion string) (*dockerService, error) {
	// Docker compose/stack prepends "stack-name_" to service name, but underscore isn't allowed in DNS names.
	// let's try looking up a "stack-name-service-name" as "stack-name_service-name"
	tmpServiceName := strings.Replace(serviceName, "-", "_", 1)
	service, err := dockerInspectService(dockerHost, tmpServiceName, tlsConfig, apiVersion)

	// stack-name might contain dash
	if err != nil && strings.Count(serviceName, "-") > 1 {
		inx := strings.Index(tmpServiceName, "-")
		for err != nil && inx != -1 && inx < len(serviceName) {
			tmpServiceName := serviceName[:inx] + strings.Replace(serviceName[inx:], "-", "_", 1)
			service, err = dockerInspectService(dockerHost, tmpServiceName, tlsConfig, apiVersion)

			if strings.Index(tmpServiceName[inx:], "-") == -1 {
				inx = strings.Index(tmpServiceName[inx:], "-")
			} else {
				inx = inx + strings.Index(tmpServiceName[inx:], "-")
			}
		}
	}
	return service, err
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

func dockerInspectService(dockerHost, containerName string, tlsConfig *tls.Config, apiVersion string) (*dockerService, error) {
	//log.Printf("[debug] dockerInspectService: serviceName %q\n", containerName)
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL '%s': %v", dockerHost, err)
	}
	client := httpClient(u, tlsConfig)
	req, err := http.NewRequest("GET", u.String()+"/"+apiVersion+"/services/"+containerName, nil)
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
	ret := dockerService{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	if err != nil {
		return nil, fmt.Errorf("failed decoding JSON response: %v", err)
	}
	return &ret, nil
}

func dockerInspectTasks(dockerHost, serviceName string, tlsConfig *tls.Config, apiVersion string) (*[]dockerTasks, error) {
	//log.Printf("[debug] dockerInspectTasks: serviceName %q\n", serviceName)
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL '%s': %v", dockerHost, err)
	}
	client := httpClient(u, tlsConfig)
	// URL: /"+apiVersion+"/tasks?filters={\"service\":[\""+serviceName+"\"],\"desired-state\":[\"running\"]}", nil)
	req, err := http.NewRequest("GET", u.String()+"/"+apiVersion+"/tasks?filters=%7B%22service%22%3A%5B%22"+serviceName+"%22%5D%2C%20%22desired-state%22%3A%5B%22running%22%5D%7D", nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %v", err)
	}
	//log.Printf("[debug] Request: %q\n", req.URL)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("not '200 OK': %v", resp.Status)
	}
	ret := []dockerTasks{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	if err != nil {
		return nil, fmt.Errorf("failed decoding JSON response: %v", err)
	}
	return &ret, nil
}

func dockerInspectNetworks(dockerHost string, tlsConfig *tls.Config, apiVersion string) (*map[string]Network, error) {
	//log.Printf("[debug] dockerInspectNetworks: \n")
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL '%s': %v", dockerHost, err)
	}
	client := httpClient(u, tlsConfig)
	// URL: /"+apiVersion+"/networks?filters={"scope":["swarm"]}", nil)
	req, err := http.NewRequest("GET", u.String()+"/"+apiVersion+"/networks?filters=%7B%22scope%22%3A%5B%22swarm%22%5D%7D", nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %v", err)
	}
	//log.Printf("[debug] Request: %q\n", req.URL)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("not '200 OK': %v", resp.Status)
	}
	nets := []Network{}
	err = json.NewDecoder(resp.Body).Decode(&nets)
	if err != nil {
		return nil, fmt.Errorf("failed decoding JSON response: %v", nets)
	}
	ret := map[string]Network{}
	for _, net := range nets {
		ret[net.Id] = net
	}
 	return &ret, nil
}

func dockerInspectNetwork(dockerHost string, networkName string, tlsConfig *tls.Config, apiVersion string) (*Network, error) {
	//log.Printf("[debug] dockerInspectNetwork: networkName %q\n", serviceName)
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL '%s': %v", dockerHost, err)
	}
	client := httpClient(u, tlsConfig)
	// URL: /"+apiVersion+"/networks/networkName", nil)
	req, err := http.NewRequest("GET", u.String()+"/"+apiVersion+"/networks/"+networkName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %v", err)
	}
	//log.Printf("[debug] Request: %q\n", req.URL)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("not '200 OK': %v", resp.Status)
	}
	net := Network{}
	err = json.NewDecoder(resp.Body).Decode(&net)
	if err != nil {
		return nil, fmt.Errorf("failed decoding JSON response: %v", net)
	}
 	return &net, nil
}
func dockerInspectNode(dockerHost string, nodeName string, tlsConfig *tls.Config, apiVersion string) (*dockerNode, error) {
	//log.Printf("[debug] dockerInspectNetwork: networkName %q\n", serviceName)
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL '%s': %v", dockerHost, err)
	}
	client := httpClient(u, tlsConfig)
	// URL: /"+apiVersion+"/networks/networkName", nil)
	req, err := http.NewRequest("GET", u.String()+"/"+apiVersion+"/nodes/"+nodeName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %v", err)
	}
	//log.Printf("[debug] Request: %q\n", req.URL)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("not '200 OK': %v", resp.Status)
	}
	ret := dockerNode{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	if err != nil {
		return nil, fmt.Errorf("failed decoding JSON response: %v", ret)
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
