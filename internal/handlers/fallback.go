package handlers

import (
	"github.com/supermetrolog/iptables/internal/netfilter"
	"log"
)

type FallbackHandler struct {
}

func (h *FallbackHandler) Handle(c netfilter.Context) (bool, error) {
	// TODO:
	log.Println("End handler")
	return false, nil
}
