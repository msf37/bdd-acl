package main

import (
	"fmt"
	"log"
	"os"

	"github.com/dalzilio/rudd"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	iface := "en0"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	bdd, err := rudd.New(1e6)
	if err != nil {
		log.Fatal(err)
	}

	policy := LoadPolicy(bdd, "policy.txt")
	fmt.Printf("Policy loaded. Listening on %s...\n", iface)

	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("pcap: %v (try running with sudo)", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp or udp"); err != nil {
		log.Fatal(err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		ipLayer := pkt.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip := ipLayer.(*layers.IPv4)
		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()

		var srcPort, dstPort, protocol int
		var protoStr string

		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			srcPort, dstPort, protocol, protoStr = int(tcp.SrcPort), int(tcp.DstPort), 1, "TCP"
		} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			srcPort, dstPort, protocol, protoStr = int(udp.SrcPort), int(udp.DstPort), 0, "UDP"
		} else {
			continue
		}

		action := CheckPacket(bdd, policy, srcIP, dstIP, srcPort, dstPort, protocol)
		color := map[string]string{"ACCEPT": "\033[32m", "DENY": "\033[31m"}[action]
		fmt.Printf("%s[%-8s]\033[0m proto=%-3s src=%s:%d dst=%s:%d\n",
			color, action, protoStr, srcIP, srcPort, dstIP, dstPort)
	}
}
