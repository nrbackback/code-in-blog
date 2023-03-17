package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	file := "pcap/trap.v1_v3.pcap"
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// packetSource.DecodeOptions.DecodeStreamsAsDatagrams = true
	idx := 0
	for packet := range packetSource.Packets() {
		// NetDataFromPacket(device, packet)
		handlePacket(packet)
		idx++
		fmt.Println(".....idx.......", idx)
	}
}

// SNMP协议一般使用UDP的161端口。
func handlePacket(packet gopacket.Packet) {
	// 解析IP层
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	// 解析UDP层
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return
	}
	// 从UDP负载中解析SNMP消息
	m, b, err := unmarshalMessage(udp.Payload)
	if err != nil {
		fmt.Println("......err.....", err)
	}
	fmt.Println(".....string(udp.Payload) return 2.....", string(b))
	fmt.Println(".....string(udp.Payload) return 1..", m.String())

	fmt.Printf("%02X .......udp.Payload.......", m.PduBytes())
	// 下面的Unmarshal步骤很重要
	rest, err := m.Pdu().Unmarshal(m.PduBytes())
	fmt.Println("......string(rest).........", string(rest))
	fmt.Println("... m.String()..", m.String())
	fmt.Println("... m.Version()..", m.Version().String())
	fmt.Println("....Pdu.PduType...", m.Pdu().PduType())
	fmt.Println("....Pdu.RequestId...", m.Pdu().RequestId())
	fmt.Println("....Pdu.ErrorStatus...", m.Pdu().ErrorStatus())
	fmt.Println("....Pdu.ErrorIndex...", m.Pdu().ErrorIndex())
	fmt.Println("....Pdu.VarBinds...", m.Pdu().VarBinds())
	// // 现在可以处理SNMP消息了，例如获取OID和值
	// oid := snmpMessage.Pdu().VarBinds().GetByIndex(0).Oid()
	// value := snmpMessage.Pdu().VarBinds().GetByIndex(0).Variable().String()
	// fmt.Println(".........oid, value......", oid, value)
}
