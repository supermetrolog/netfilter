package iptables

import (
	"fmt"
	"net"
)

type ChainName string

const (
	Prerouting  ChainName = "prerouting"
	Forward     ChainName = "forward"
	Input       ChainName = "input"
	Output      ChainName = "output"
	Postrouting ChainName = "postrouting"
)

type NetSettings interface {
	IpForwardingEnabled() bool
	Interfaces() []string // TODO:
}

type Context interface {
	Packet() *Packet
	Jump(chain string) (bool, error)
	NetSettings() NetSettings
}

type Handler interface {
	Handle(c Context) (bool, error)
}

type Middleware interface {
	Handle(c Context, next Handler) (bool, error)
}

type Pipeline interface {
	Handler
	Pipe(Handler)
}

type Packet struct {
	srcIp    net.IP
	srcPort  uint16
	dstIp    net.IP
	dstPort  uint16
	protocol string
}

type Settings struct {
	interfaces          []string
	ipForwardingEnabled bool
}

func (s Settings) Interfaces() []string {
	return s.interfaces
}

func (s Settings) IpForwardingEnabled() bool {
	return s.ipForwardingEnabled
}

type IpTables struct {
	first       Pipeline
	chains      map[string]Pipeline
	netSettings NetSettings
	packet      *Packet
}

func NewIpTables(settings NetSettings, pack *Packet) *IpTables {
	return &IpTables{
		chains:      make(map[string]Pipeline),
		netSettings: settings,
		packet:      pack,
	}
}

func (ipt *IpTables) Run() error {
	_, err := ipt.first.Handle(ipt)

	if err != nil {
		return fmt.Errorf("processing pipline error: %w", err)
	}

	return nil
}

func (ipt *IpTables) Packet() *Packet {
	return ipt.packet
}

func (ipt *IpTables) NetSettings() NetSettings {
	return ipt.netSettings
}

func (ipt *IpTables) Jump(chain string) (bool, error) {
	p, exists := ipt.chains[chain]

	if exists {
		return false, fmt.Errorf("chain with name %s not found", chain)
	}

	return p.Handle(ipt)
}
