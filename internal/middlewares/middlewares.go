package middlewares

import (
	"github.com/supermetrolog/iptables/internal/netfilter"
	"log"
)

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
