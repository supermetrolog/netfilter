package netfilter

import (
	"fmt"
	"github.com/supermetrolog/iptables/internal/handlers"
)

func (nf *NetFilter) createDefaultChainsAndTables() {
	nf.SetChain(Prerouting, Raw, &handlers.AcceptPoliticHandler{})
	nf.SetChain(Prerouting, Mangle, &handlers.AcceptPoliticHandler{})
	nf.SetChain(Prerouting, Nat, &handlers.AcceptPoliticHandler{})

	nf.SetChain(Forward, Mangle, &handlers.AcceptPoliticHandler{})
	nf.SetChain(Forward, Filter, &handlers.AcceptPoliticHandler{})

	nf.SetChain(Input, Mangle, &handlers.AcceptPoliticHandler{})
	nf.SetChain(Input, Filter, &handlers.AcceptPoliticHandler{})

	nf.SetChain(Output, Raw, &handlers.AcceptPoliticHandler{})
	nf.SetChain(Output, Mangle, &handlers.AcceptPoliticHandler{})
	nf.SetChain(Output, Nat, &handlers.AcceptPoliticHandler{})
	nf.SetChain(Output, Filter, &handlers.AcceptPoliticHandler{})

	nf.SetChain(Postrouting, Mangle, &handlers.AcceptPoliticHandler{})
	nf.SetChain(Postrouting, Nat, &handlers.AcceptPoliticHandler{})
}

func (nf *NetFilter) HandleChain(ctx Context, c Chain) (bool, error) {
	ch := nf.chains[c]
	for _, t := range ch.tables {
		result, err := t.pipeline.Handle(ctx, t.politic)

		if err != nil {
			return false, fmt.Errorf("chain: %s; table: %s; processing error: %w", t.ch, t.tab, err)
		}

		if !result {
			return false, nil
		}
	}

	return true, nil
}
