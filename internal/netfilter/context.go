package netfilter

import "fmt"

type PipelineContext struct {
	nf     *NetFilter
	pack   Packet
	states []*State
}

func NewPipelineContext(nf *NetFilter, pack Packet) *PipelineContext {
	return &PipelineContext{nf: nf, pack: pack}
}

func (pc *PipelineContext) Packet() Packet {
	return pc.pack
}

func (pc *PipelineContext) NetSettings() NetSettings {
	return pc.nf.netSettings
}

func (pc *PipelineContext) StoreState(state *State) {
	pc.states = append(pc.states, state)
}

func (pc *PipelineContext) States() []*State {
	return pc.states
}

func (pc *PipelineContext) Jump(c Chain, t Table) (bool, error) {
	tab, exists := pc.nf.tables[c][t]

	if exists {
		return false, fmt.Errorf("chain: %s not found in table: %s", c, t)
	}

	return tab.pipeline.Handle(pc, tab.politic)
}
