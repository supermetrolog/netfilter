package pipeline

import (
	"errors"
	"github.com/supermetrolog/iptables/internal/netfilter"
	"github.com/supermetrolog/iptables/pkg/queue"
)

type Pipeline struct {
	handlers queue.Queue
}

func New() *Pipeline {
	return &Pipeline{}
}

func (p *Pipeline) Pipe(handler netfilter.Middleware) {
	p.handlers.Enqueue(handler)
}

func (p *Pipeline) Handle(c netfilter.Context, handler netfilter.Handler) (bool, error) {
	if handler == nil {
		return false, errors.New("handler can not be nil")
	}

	n := newNext(p.handlers, handler)
	return n.Next(c)
}
