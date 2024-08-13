package handlers

import (
	"github.com/supermetrolog/iptables/internal/netfilter"
	"log"
)

type LocalProcessHandler struct {
}

func (h *LocalProcessHandler) Handle(c netfilter.Context) (bool, error) {
	// TODO:
	log.Println("Local Process Handler")
	return true, nil
}
