package pipeline

import "github.com/supermetrolog/iptables/internal/netfilter"

type Factory struct{}

func NewFactory() *Factory {
	return &Factory{}
}

func (f Factory) Create() netfilter.Pipeline {
	return New()
}
