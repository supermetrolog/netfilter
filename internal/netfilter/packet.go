package netfilter

import "net"

type Protocol string

const (
	Tcp  Protocol = "tcp"
	Udp  Protocol = "udp"
	Icmp Protocol = "icmp"
)

type Packet interface {
	SrcIp() *net.IP
	SrcPort() uint16
	DstIp() *net.IP
	DstPort() uint16
	Protocol() Protocol

	SetSrcIp(ip *net.IP)
	SetSrcPort(port uint16)
	SetDstIp(ip *net.IP)
	SetDsPort(port uint16)
}
