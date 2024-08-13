package netfilter

import (
	"fmt"
	"github.com/supermetrolog/iptables/internal/pipeline"
)

type Chain string
type Table string

const (
	Prerouting  Chain = "prerouting"
	Forward     Chain = "forward"
	Input       Chain = "input"
	Output      Chain = "output"
	Postrouting Chain = "postrouting"
)

const (
	Raw    Table = "raw"
	Mangle Table = "mangle"
	Nat    Table = "nat"
	Filter Table = "filter"
)

type NetSettings interface {
	IpForwardingEnabled() bool
	Interfaces() []string // TODO:
}

type Context interface {
	Packet() Packet
	StoreState(state *State)
	Jump(c Chain, t Table) (bool, error)
	NetSettings() NetSettings
}

type Handler interface {
	Handle(c Context) (bool, error)
}

type Middleware interface {
	Handle(c Context, next Handler) (bool, error)
}

type Pipeline interface {
	Middleware
	Pipe(Middleware)
}

type Settings struct {
	interfaces          []string
	ipForwardingEnabled bool
}

func (s Settings) Interfaces() []string {
	return s.interfaces
}

func (s Settings) IpForwardingEnabled() bool {
	return s.ipForwardingEnabled
}

type State struct {
	Pack Packet
	Meta any
	Info string
}

type Rule struct {
	Ch         Chain
	Tab        Table
	Middleware Middleware
}

type chain struct {
	tables []*table
}

func newChain() *chain {
	return &chain{
		tables: make([]*table, 0),
	}
}

type table struct {
	tab      Table
	ch       Chain
	pipeline Pipeline
	politic  Handler
}

func newTable(c Chain, t Table, p Pipeline, politic Handler) *table {
	return &table{
		tab:      t,
		ch:       c,
		pipeline: p,
		politic:  politic,
	}
}

type NetFilter struct {
	endHandler          Handler
	localProcessHandler Handler
	pipelineFactory     pipeline.Factory
	chains              map[Chain]*chain
	tables              map[Chain]map[Table]*table
	netSettings         NetSettings
}

func New(endHandler Handler, localProcessHandler Handler, settings NetSettings, pipelineFactory pipeline.Factory) *NetFilter {
	nf := &NetFilter{
		chains:              make(map[Chain]*chain),
		tables:              make(map[Chain]map[Table]*table),
		endHandler:          endHandler,
		localProcessHandler: localProcessHandler,
		netSettings:         settings,
		pipelineFactory:     pipelineFactory,
	}

	nf.createDefaultChainsAndTables()

	return nf
}

func (nf *NetFilter) AppendRule(r Rule) error {
	if tab, exists := nf.tables[r.Ch][r.Tab]; exists {
		tab.pipeline.Pipe(r.Middleware)
		return nil
	}

	return fmt.Errorf("unable append rule; chain: %s not found in table: %s", r.Ch, r.Tab)
}

func (nf *NetFilter) SetChain(c Chain, t Table, politic Handler) {
	if tab, exists := nf.tables[c][t]; exists {
		tab.politic = politic
		return
	}

	tab := newTable(c, t, nf.pipelineFactory.Create(), politic)

	nf.tables[c][t] = tab

	if ch, exists := nf.chains[c]; exists {
		ch.tables = append(ch.tables, tab)
	} else {
		ch = newChain()
		ch.tables = append(ch.tables, tab)
		nf.chains[c] = ch
	}
}

func (nf *NetFilter) Run(pack Packet) ([]*State, error) {
	ctx := NewPipelineContext(nf, pack)

	result, err := nf.HandleChain(ctx, Prerouting)
	if err != nil {
		return nil, err
	}
	if !result {
		return ctx.States(), nil
	}

	// TODO: check target ip
	if nf.netSettings.IpForwardingEnabled() {
		result, err = nf.HandleChain(ctx, Forward)
		if err != nil {
			return nil, err
		}
		if !result {
			return ctx.States(), nil
		}

		result, err = nf.HandleChain(ctx, Postrouting)
		if err != nil {
			return nil, err
		}
		if !result {
			return ctx.States(), nil
		}
	} else {
		result, err = nf.HandleChain(ctx, Input)
		if err != nil {
			return nil, err
		}
		if !result {
			return ctx.States(), nil
		}

		result, err = nf.localProcessHandler.Handle(ctx)
		if err != nil {
			return nil, err
		}
		if !result {
			return ctx.States(), nil
		}

		result, err = nf.HandleChain(ctx, Output)
		if err != nil {
			return nil, err
		}
		if !result {
			return ctx.States(), nil
		}

		result, err = nf.HandleChain(ctx, Postrouting)
		if err != nil {
			return nil, err
		}
		if !result {
			return ctx.States(), nil
		}

		result, err = nf.endHandler.Handle(ctx)
		if err != nil {
			return nil, err
		}
		if !result {
			return ctx.States(), nil
		}
	}

	return ctx.States(), nil
}
