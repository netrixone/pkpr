package monitor

import (
	"encoding/json"
	"os"
	"slices"
	"strings"

	"github.com/netrixone/naabu-probe/pkg/port"
	"github.com/netrixone/naabu-probe/pkg/result"
	"github.com/projectdiscovery/gologger"
	iputil "github.com/projectdiscovery/utils/ip"
	"main/pkg/whitelist"
)

type AlertCallback func(alert *Alert)

type Monitor struct {
	Alerts    []*Alert
	OnAlert   AlertCallback
	whitelist whitelist.Whitelist
	seenIPs   map[string]bool
}

func New(wl whitelist.Whitelist) *Monitor {
	return &Monitor{
		Alerts:    make([]*Alert, 0),
		OnAlert:   func(alert *Alert) {},
		whitelist: wl,
		seenIPs:   make(map[string]bool),
	}
}

func (m *Monitor) Close() {
	// Iterate over all remaining (not seen) IPs in the whitelist.
	for ip, whitelistedHost := range m.whitelist {
		if !m.seenIPs[ip] {
			// Find closed ports that should be open.
			for _, currentPort := range whitelistedHost.Ports {
				alert := NewUnknownPort(whitelistedHost, currentPort)
				m.Alerts = append(m.Alerts, alert)
				gologger.Warning().Msgf("%s\n", alert)
			}
		}
	}
}

func (m *Monitor) Evaluate(res *result.HostResult) {
	if res.Host == "" || res.Host == res.IP {
		res.Host = ""

		// Do a reverse PTR query for a given IP.
		names, err := iputil.ToFQDN(res.IP)
		if err != nil {
			gologger.Debug().Msgf("reverse ptr failed for %s: %s\n", res.IP, err)
		} else {
			res.Host = strings.Trim(names[0], ".")
		}
	}

	// Find open ports that should not be open.
	whitelistedHost := m.whitelist[res.IP]
	for _, currentPort := range res.Ports {
		whitelisted := false
		if whitelistedHost != nil {
			whitelisted = slices.ContainsFunc(whitelistedHost.Ports, func(port *whitelist.Port) bool {
				return port.Port == currentPort.Port && port.Protocol == currentPort.Protocol
			})
		}

		if !whitelisted {
			alert := NewOpenPort(res, currentPort)
			m.Alerts = append(m.Alerts, alert)
			gologger.Error().Msgf("%s\n", alert)
		}
	}

	if whitelistedHost != nil {
		// Find closed ports that should be open.
		for _, currentPort := range whitelistedHost.Ports {
			open := slices.ContainsFunc(res.Ports, func(port *port.Port) bool {
				return port.Port == currentPort.Port && port.Protocol == currentPort.Protocol
			})

			if !open {
				alert := NewClosedPort(res, currentPort)
				m.Alerts = append(m.Alerts, alert)
				gologger.Warning().Msgf("%s\n", alert)
			}
		}
	}

	m.seenIPs[res.IP] = true
}

func (m *Monitor) WriteAsJson(destination string) error {
	data, err := json.Marshal(m.Alerts)
	if err != nil {
		return err
	}

	return os.WriteFile(destination, data, 0644)
}
