package handlers

import "github.com/supermetrolog/iptables/internal/iptables"

type AcceptPolitic struct {
}

func (p *AcceptPolitic) Handle(c iptables.Context) (bool, error) {
	return true, nil
}

type DropPolitic struct {
}

func (p *DropPolitic) Handle(c iptables.Context) (bool, error) {
	return false, nil
}

type RejectPolitic struct {
}

func (p *RejectPolitic) Handle(c iptables.Context) (bool, error) {
	return false, nil
}
