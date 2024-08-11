package main

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

}
