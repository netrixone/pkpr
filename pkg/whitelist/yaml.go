package whitelist

import (
	"strings"

	"github.com/netrixone/naabu-probe/pkg/protocol"
	"gopkg.in/yaml.v3"
)

type YamlInput []YamlEntry

type YamlEntry struct {
	Names string         `yaml:"host"`
	Tcp   map[int]string `yaml:"tcp"`
	Udp   map[int]string `yaml:"udp"`
}

func (ye YamlEntry) parseNames() []string {
	names := strings.Split(ye.Names, ",")
	for i := range names {
		names[i] = strings.TrimSpace(names[i])
	}
	return names
}

func (ye YamlEntry) parsePorts() []*Port {
	ports := make([]*Port, 0, len(ye.Tcp)+len(ye.Udp))
	for port, label := range ye.Tcp {
		ports = append(ports, &Port{Port: port, Label: label, Protocol: protocol.TCP})
	}
	for port, label := range ye.Udp {
		ports = append(ports, &Port{Port: port, Label: label, Protocol: protocol.UDP})
	}
	return ports
}

func UnmarshalYaml(data []byte) (YamlInput, error) {
	input := YamlInput{}
	if err := yaml.Unmarshal(data, &input); err != nil {
		return nil, err
	}

	// @todo: add validation

	return input, nil
}
