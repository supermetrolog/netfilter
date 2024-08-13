package pipeline

import (
	"errors"
	"github.com/supermetrolog/iptables/internal/netfilter"
	"github.com/supermetrolog/iptables/pkg/queue"
)

type next struct {
	handler  netfilter.Handler
	Handlers queue.Queue
}

func newNext(q queue.Queue, handler netfilter.Handler) next {
	return next{
		Handlers: q,
		handler:  handler,
	}
}
func (n next) Next(c netfilter.Context) (bool, error) {
	if n.Handlers.IsEmpty() {
		return n.handler.Handle(c)
	}

	current, ok := n.Handlers.Dequeue().(netfilter.Middleware)
	if !ok {
		return false, errors.New("unknown item in Handlers Queue")
	}

	return current.Handle(c, nextWrapper{n: &n})
}

type nextWrapper struct {
	n *next
}

func (n nextWrapper) Handle(c netfilter.Context) (bool, error) {
	return n.n.Next(c)
}
