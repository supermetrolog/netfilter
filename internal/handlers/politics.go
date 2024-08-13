package handlers

import "github.com/supermetrolog/iptables/internal/netfilter"

type AcceptPoliticHandler struct {
}

func (p *AcceptPoliticHandler) Handle(c netfilter.Context) (bool, error) {
	return true, nil
}

type DropPoliticHandler struct {
}

func (p *DropPoliticHandler) Handle(c netfilter.Context) (bool, error) {
	return false, nil
}

type RejectPoliticHandler struct {
}

func (p *RejectPoliticHandler) Handle(c netfilter.Context) (bool, error) {
	return false, nil
}
