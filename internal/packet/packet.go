package packet

import (
	"github.com/supermetrolog/iptables/internal/netfilter"
	"net"
)

type Packet struct {
	srcIp    *net.IP
	srcPort  uint16
	dstIp    *net.IP
	dstPort  uint16
	protocol netfilter.Protocol
}

func NewPacket(srcIp *net.IP, srcPort uint16, dstIp *net.IP, dstPort uint16, protocol netfilter.Protocol) *Packet {
	return &Packet{srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort, protocol: protocol}
}

func (p *Packet) SrcIp() *net.IP {
	return p.srcIp
}

func (p *Packet) SrcPort() uint16 {
	return p.srcPort

}

func (p *Packet) DstIp() *net.IP {
	return p.dstIp

}

func (p *Packet) DstPort() uint16 {
	return p.dstPort

}

func (p *Packet) Protocol() netfilter.Protocol {
	return p.protocol
}

func (p *Packet) SetSrcIp(ip *net.IP) {
	p.srcIp = ip

}

func (p *Packet) SetSrcPort(port uint16) {
	p.srcPort = port
}

func (p *Packet) SetDstIp(ip *net.IP) {
	p.dstIp = ip
}

func (p *Packet) SetDsPort(port uint16) {
	p.dstPort = port
}
