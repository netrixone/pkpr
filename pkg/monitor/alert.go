package monitor

import (
	"fmt"
	"strings"

	"github.com/netrixone/naabu-probe/pkg/port"
	"github.com/netrixone/naabu-probe/pkg/result"
	"main/pkg/whitelist"
)

type Severity string

const (
	SeverityErr  Severity = "ERR"
	SeverityWarn Severity = "WARN"
)

type Alert struct {
	Host     string         `json:"host"`
	IP       string         `json:"ip"`
	Port     whitelist.Port `json:"port"`
	Open     bool           `json:"open"`
	Severity Severity       `json:"severity"`
}

func NewOpenPort(res *result.HostResult, p *port.Port) *Alert {
	return &Alert{
		Host: res.Host,
		IP:   res.IP,
		Port: whitelist.Port{
			Port:     p.Port,
			Label:    p.Label,
			Protocol: p.Protocol,
		},
		Open:     true,
		Severity: SeverityErr,
	}
}

func NewClosedPort(res *result.HostResult, p *whitelist.Port) *Alert {
	return &Alert{
		Host: res.Host,
		IP:   res.IP,
		Port: whitelist.Port{
			Port:     p.Port,
			Label:    p.Label,
			Protocol: p.Protocol,
		},
		Open:     false,
		Severity: SeverityWarn,
	}
}

func NewUnknownPort(res *whitelist.Host, p *whitelist.Port) *Alert {
	return &Alert{
		Host: res.Name(),
		IP:   res.IP,
		Port: whitelist.Port{
			Port:     p.Port,
			Label:    p.Label,
			Protocol: p.Protocol,
		},
		Open:     false,
		Severity: SeverityWarn,
	}
}

func (a *Alert) String() string {
	portLabel := ""
	if a.Port.Label != "" {
		portLabel = fmt.Sprintf(" (%s)", a.Port.Label)
	}

	hostStr := a.IP
	if a.Host != "" && a.Host != a.IP {
		hostStr += fmt.Sprintf(" (%s)", a.Host)
	}

	status := "CLOSED"
	defStatus := "open"
	if a.Open {
		status = "OPEN"
		defStatus = "closed"
	}

	return fmt.Sprintf("Port %s/%d%s on %s is %s but should be %s!",
		strings.ToUpper(a.Port.Protocol.String()), a.Port.Port, portLabel, hostStr, status, defStatus,
	)
}
