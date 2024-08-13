package netconfig

type NetConfig struct {
	interfaces   []string
	ipForwarding bool
}

func New() *NetConfig {
	return &NetConfig{interfaces: make([]string, 0)}
}

func (n *NetConfig) WithInterface(iface string) *NetConfig {
	n.interfaces = append(n.interfaces, iface)
	return n
}

func (n *NetConfig) IpForwarding() *NetConfig {
	n.ipForwarding = true
	return n
}

func (s *NetConfig) Interfaces() []string {
	return s.interfaces
}

func (s *NetConfig) IsIpForwardEnabled() bool {
	return s.ipForwarding
}
