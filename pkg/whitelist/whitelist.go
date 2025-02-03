package whitelist

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/netrixone/naabu-probe/pkg/protocol"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	iputil "github.com/projectdiscovery/utils/ip"
)

var DNSClient *dnsx.DNSX

func init() {
	c, err := defaultDNSClient()
	if err != nil {
		gologger.Error().Msgf("Could not init a DNS client: %s\n", err)
	}
	DNSClient = c
}

var Empty = Whitelist{}

type Whitelist map[string]*Host

func NewFromYaml(yaml YamlInput) Whitelist {
	wl := Whitelist{}
	for _, yHost := range yaml {
		yHostNames := yHost.parseNames()
		yHostPorts := yHost.parsePorts()

		for _, yHostName := range yHostNames {
			if iputil.IsIP(yHostName) {
				ip := yHostName
				name := ""

				// Do a reverse PTR query for a given IP.
				names, err := iputil.ToFQDN(ip)
				if err != nil {
					gologger.Debug().Msgf("Reverse PTR failed for %s: %s\n", ip, err)
				} else {
					name = strings.Trim(names[0], ".")
				}

				wl[ip] = &Host{
					IP:    ip,
					Names: []string{name},
					Ports: yHostPorts,
				}

			} else {
				ips, err := hostname2ips(yHostName)
				if err != nil {
					gologger.Error().Msgf("Hostname resolution failed for %s: %s\n", yHostName, err)
				}

				for _, ip := range ips {
					wl[ip] = &Host{
						IP:    ip,
						Names: yHostNames,
						Ports: yHostPorts,
					}
				}
			}
		}
	}
	return wl
}

type Host struct {
	IP    string
	Names []string
	Ports []*Port
}

func (h *Host) Name() string {
	if len(h.Names) == 0 {
		return ""
	}
	return h.Names[0]
}

type Port struct {
	Port     int
	Label    string
	Protocol protocol.Protocol
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d", p.Port, p.Protocol)
}

func Load(filename string) (Whitelist, error) {
	inputFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer inputFile.Close()

	inputData, err := io.ReadAll(inputFile)
	if err != nil {
		return nil, err
	}

	yaml, err := UnmarshalYaml(inputData)
	if err != nil {
		return nil, err
	}

	return NewFromYaml(yaml), nil
}

func defaultDNSClient() (*dnsx.DNSX, error) {
	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = 3
	dnsOptions.Hostsfile = true

	// @todo: add support for AAAA if needed
	return dnsx.New(dnsOptions)
}

func hostname2ips(host string) ([]string, error) {
	dnsData, err := DNSClient.QueryMultiple(host)
	if err != nil || dnsData == nil {
		gologger.Warning().Msgf("Could not get IP for host: %s\n", host)
		return nil, err
	}
	return dnsData.A, nil
}
