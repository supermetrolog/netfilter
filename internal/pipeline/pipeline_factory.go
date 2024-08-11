package pipeline

import "github.com/supermetrolog/iptables/internal/iptables"

type Factory struct{}

func NewFactory() *Factory {
	return &Factory{}
}

func (f Factory) Create() iptables.Pipeline {
	return New()
}
