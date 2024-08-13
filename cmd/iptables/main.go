package main

import (
	"github.com/supermetrolog/iptables/internal/handlers"
	"github.com/supermetrolog/iptables/internal/middlewares"
	"github.com/supermetrolog/iptables/internal/netconfig"
	"github.com/supermetrolog/iptables/internal/netfilter"
	"github.com/supermetrolog/iptables/internal/packet"
	"github.com/supermetrolog/iptables/internal/pipeline"
	"log"
	"net"
)

func main() {
	// iptables -t FILTER -P INPUT DROP

	// iptables -t FILTER -A INPUT -p tcp --dport 80 -j ACCEPT
	// iptables -t FILTER -A INPUT -p tcp -s 1.1.1.1/32 -j DROP

	// pipeline := NewPipeline()

	// preRoutingChain := NewPipeline()
	// preRoutingRawTable := NewPipeline()
	// preRoutingMangleTable := NewPipeline()
	// preRoutingNatTable := NewPipeline()

	// preRoutingChain.Add(preRoutingRawTable)
	// preRoutingChain.Add(preRoutingMangleTable)
	// preRoutingChain.Add(preRoutingNatTable)

	// inputChain := NewPipeline()

	// inputChain.Add(AcceptTcpWithPort80)
	// inputChain.Add(DropTcpForIP)

	// inputChain.Add(DropPolitic)

	netCfg := netconfig.New().IpForwarding().WithInterface("10.10.0.0/24")

	nf := netfilter.New(
		&handlers.FallbackHandler{},
		&handlers.LocalProcessHandler{},
		netCfg,
		pipeline.NewFactory(),
	)

	err := nf.AppendRule(netfilter.Rule{
		Tab:        netfilter.Raw,
		Ch:         netfilter.Prerouting,
		Middleware: middlewares.NewCheckProtocolMiddleware(netfilter.Tcp),
	})

	if err != nil {
		log.Fatal(err)
	}

	srcIp := net.IPv4(211, 1, 1, 1)
	dstIp := net.IPv4(10, 10, 10, 10)
	pack := packet.NewPacket(&srcIp, 3000, &dstIp, 80, netfilter.Tcp)

	states, err := nf.Run(pack)

	if err != nil {
		log.Fatalf("netfilter error: %s", err)
	}

	log.Println(states)
}
