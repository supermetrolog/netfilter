package pipeline

import (
	"errors"
	"github.com/supermetrolog/iptables/internal/iptables"
	"github.com/supermetrolog/iptables/pkg/queue"
)

type next struct {
	handler  iptables.Handler
	Handlers queue.Queue
}

func newNext(q queue.Queue, handler iptables.Handler) next {
	return next{
		Handlers: q,
		handler:  handler,
	}
}
func (n next) Next(c iptables.Context) (bool, error) {
	if n.Handlers.IsEmpty() {
		return n.handler.Handle(c)
	}

	current, ok := n.Handlers.Dequeue().(iptables.Middleware)
	if !ok {
		return false, errors.New("unknown item in Handlers Queue")
	}

	return current.Handle(c, nextWrapper{n: &n})
}

type nextWrapper struct {
	n *next
}

func (n nextWrapper) Handle(c iptables.Context) (bool, error) {
	return n.n.Next(c)
}
