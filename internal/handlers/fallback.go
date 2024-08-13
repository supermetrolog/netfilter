package handlers

import "github.com/supermetrolog/iptables/internal/netfilter"

type FallbackHandler struct {
}

func (h *FallbackHandler) Handle(c netfilter.Context) (bool, error) {
	// TODO:
	return false, nil
}

type PreroutingFallbackHandler struct {
}

func (h *PreroutingFallbackHandler) Handle(c netfilter.Context) (bool, error) {
	// TODO: jump to FORWARD OR INPUT CHAIN
	return false, nil
}
