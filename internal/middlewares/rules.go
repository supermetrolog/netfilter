package middlewares

import (
	"github.com/supermetrolog/iptables/internal/netfilter"
	"log"
	"net"
)

type Rule struct {
	rule            string
	srcIp           *net.IP // TODO: remove
	pipelineFactory netfilter.PipelineFactory
}

func NewRule(rule string, pipelineFactory netfilter.PipelineFactory, srcIp *net.IP) *Rule {
	return &Rule{rule: rule, pipelineFactory: pipelineFactory, srcIp: srcIp}
}

func (h *Rule) Handle(c netfilter.Context, next netfilter.Handler) (bool, error) {
	log.Printf("Process rule: %s", h.rule)

	c.StoreState(&netfilter.State{
		Pack:  c.Packet(),
		Table: c.Table(),
		Chain: c.Chain(),
		Info:  h.rule,
	})

	pipeline := h.pipelineFactory.Create()

	// TODO: parse iptables rule
	pipeline.Pipe(NewCheckProtocolMiddleware(netfilter.Tcp))
	pipeline.Pipe(NewCheckSrcIpMiddleware(h.srcIp))

	res, err := pipeline.Handle(c, &netfilter.AcceptPoliticHandler{})

	if err != nil {
		return false, err
	}

	if !res {
		return false, nil
	}

	return next.Handle(c)
}
