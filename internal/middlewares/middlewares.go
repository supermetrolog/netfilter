package middlewares

import (
	"github.com/supermetrolog/iptables/internal/netfilter"
	"log"
	"net"
)

type CheckSrcIpMiddleware struct {
	ip *net.IP
}

func NewCheckSrcIpMiddleware(ip *net.IP) *CheckSrcIpMiddleware {
	return &CheckSrcIpMiddleware{ip: ip}
}

func (h *CheckSrcIpMiddleware) Handle(c netfilter.Context, next netfilter.Handler) (bool, error) {
	log.Println("Check src ip middleware")

	if c.Packet().SrcIp() != h.ip {
		return false, nil
	}

	return next.Handle(c)
}

type CheckProtocolMiddleware struct {
	protocol netfilter.Protocol
}

func NewCheckProtocolMiddleware(protocol netfilter.Protocol) *CheckProtocolMiddleware {
	return &CheckProtocolMiddleware{protocol: protocol}
}

func (h *CheckProtocolMiddleware) Handle(c netfilter.Context, next netfilter.Handler) (bool, error) {
	log.Println("Check protocol middleware")

	if c.Packet().Protocol() != h.protocol {
		return false, nil
	}

	return next.Handle(c)
}

type StoreStateMiddleware struct {
	rule string
}

func NewStoreStateMiddleware(rule string) *StoreStateMiddleware {
	return &StoreStateMiddleware{rule: rule}
}

func (h *StoreStateMiddleware) Handle(c netfilter.Context, next netfilter.Handler) (bool, error) {

	res, err := next.Handle(c)

	log.Println("Store state middleware")
	c.StoreState(&netfilter.State{
		Pack:  c.Packet(),
		Table: c.Table(),
		Chain: c.Chain(),
		Info:  h.rule,
	})

	return res, err
}
