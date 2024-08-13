package netfilter

import (
	"fmt"
)

func (nf *NetFilter) createDefaultChainsAndTables() {
	nf.SetChain(Prerouting, Raw, &AcceptPoliticHandler{})
	nf.SetChain(Prerouting, Mangle, &AcceptPoliticHandler{})
	nf.SetChain(Prerouting, Nat, &AcceptPoliticHandler{})

	nf.SetChain(Forward, Mangle, &AcceptPoliticHandler{})
	nf.SetChain(Forward, Filter, &AcceptPoliticHandler{})

	nf.SetChain(Input, Mangle, &AcceptPoliticHandler{})
	nf.SetChain(Input, Filter, &AcceptPoliticHandler{})

	nf.SetChain(Output, Raw, &AcceptPoliticHandler{})
	nf.SetChain(Output, Mangle, &AcceptPoliticHandler{})
	nf.SetChain(Output, Nat, &AcceptPoliticHandler{})
	nf.SetChain(Output, Filter, &AcceptPoliticHandler{})

	nf.SetChain(Postrouting, Mangle, &AcceptPoliticHandler{})
	nf.SetChain(Postrouting, Nat, &AcceptPoliticHandler{})
}

func (nf *NetFilter) HandleChain(ctx Context, c Chain) (bool, error) {
	ch := nf.chains[c]
	for _, t := range ch.tables {
		ctx.SetChain(t.ch)
		ctx.SetTable(t.tab)
		
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
