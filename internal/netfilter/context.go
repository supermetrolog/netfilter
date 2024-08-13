package netfilter

import "fmt"

type pipelineContext struct {
	nf     *NetFilter
	pack   Packet
	states []*State
}

func newPipelineContext(nf *NetFilter, pack Packet) *pipelineContext {
	return &pipelineContext{nf: nf, pack: pack}
}

func (pc *pipelineContext) Packet() Packet {
	return pc.pack
}

func (pc *pipelineContext) NetConfig() NetConfig {
	return pc.nf.netConfig
}

func (pc *pipelineContext) StoreState(state *State) {
	pc.states = append(pc.states, state)
}

func (pc *pipelineContext) States() []*State {
	return pc.states
}

func (pc *pipelineContext) Jump(c Chain, t Table) (bool, error) {
	tab, exists := pc.nf.tables[c][t]

	if exists {
		return false, fmt.Errorf("chain: %s not found in table: %s", c, t)
	}

	return tab.pipeline.Handle(pc, tab.politic)
}
