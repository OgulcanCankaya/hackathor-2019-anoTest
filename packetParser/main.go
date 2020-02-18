package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/subosito/gotenv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Header struct {
	Key   string
	Value string
}

type httpPacket struct {
	Method      string
	Dir         string
	HTTPVersion string
	Headers     []Header
	Content     string
	SrcIP       string
	DstIP       string
	SrcMac      string
	DstMac      string
}

var Packets []httpPacket

// func handlePacket(packet gopacket.Packet) {
// 	//packet_d := new (packet_data)
// 	if packet.ApplicationLayer() != nil {
// 		payload := packet.ApplicationLayer().Payload()
// 		str := string(payload[:])
// 		//println(str)

// 		var HttpPacket httpPacket

// 		str_arr := strings.Split(str, "\n")
// 		//fmt.Println(str_arr)
// 		first_line := strings.Split(str_arr[0], " ")

// 		HttpPacket.Method = first_line[0]
// 		HttpPacket.Dir = first_line[1]
// 		HttpPacket.HTTPVersion = first_line[2]
// 		//fmt.Println(HttpPacket.Headers)
// 		for _, header_str := range str_arr[1 : len(str_arr)-2] {
// 			header_arr := strings.Split(string(header_str), ": ")

// 			var header2 Header

// 			header2.Key = header_arr[0]
// 			header2.Value = header_arr[1]
// 			//fmt.Println(header2)
// 			HttpPacket.Headers = append(HttpPacket.Headers, header2)
// 			//fmt.Println("{:#?}",HttpPacket.Headers)

// 		}

// 		HttpPacket.Content = str_arr[len(str_arr)-1]

// 		Packets = append(Packets, HttpPacket)

// 	}
// }

func handleLivePacket(packet gopacket.Packet) {
	gotenv.Load()

	//packet_d := new (packet_data)
	// if packet.ApplicationLayer() != nil || packet.NetworkLayer().NetworkFlow().Src().String() == os.Getenv("MY_IP") {
	if packet.ApplicationLayer() != nil && packet.TransportLayer().TransportFlow().Src().String() == os.Getenv("LISTEN_PORT") && packet.NetworkLayer().NetworkFlow().Src().String() == os.Getenv("MY_IP") {
		fmt.Println(packet)
		fmt.Println(packet.TransportLayer().TransportFlow().Src().String())

		payload := packet.ApplicationLayer().Payload()
		str := string(payload)
		//println(str)

		var HttpPacket httpPacket

		str_arr := strings.Split(str, "\n")
		//fmt.Println(str_arr)
		first_line := strings.Split(str_arr[0], " ")

		if len(first_line) > 2 {
			HttpPacket.Method = first_line[0]
			HttpPacket.Dir = first_line[1]
			HttpPacket.HTTPVersion = first_line[2]
			//fmt.Println(HttpPacket.Headers)
			for _, header_str := range str_arr[1 : len(str_arr)-2] {
				header_arr := strings.Split(string(header_str), ": ")
				if len(header_arr) > 1 {
					var header2 Header

					header2.Key = header_arr[0]
					header2.Value = header_arr[1]
					//fmt.Println(header2)
					HttpPacket.Headers = append(HttpPacket.Headers, header2)
					//fmt.Println("{:#?}",HttpPacket.Headers)
				}
			}

			HttpPacket.Content = str_arr[len(str_arr)-1]

			HttpPacket.DstIP = packet.NetworkLayer().NetworkFlow().Dst().String()
			HttpPacket.SrcIP = packet.NetworkLayer().NetworkFlow().Src().String()
			HttpPacket.SrcMac = packet.LinkLayer().LinkFlow().Src().String()
			HttpPacket.DstMac = packet.LinkLayer().LinkFlow().Dst().String()

			// Packets = append(Packets, HttpPacket)

			data, _ := json.Marshal(&HttpPacket)
			fmt.Println(string(data))

			resp, _ := http.Post("http://"+os.Getenv("POST_IP")+":"+os.Getenv("POST_PORT")+"/http", "application/json", bytes.NewBuffer(data))
			println(resp)
		}

	}
}

func main() {
	fmt.Println("jskglsdgs")
	gotenv.Load()

	// if handle, err := pcap.OpenOffline("/home/ogulcan/go/src/hackathor/main.pcap"); err != nil {
	// 	panic(err)
	// } else {
	// 	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// 	for packet := range packetSource.Packets() {
	// 		handlePacket(packet)  // Do something with a packet here.
	// 	}

	// }

	fmt.Println("sdf: ", os.Getenv("LISTEN_PORT"))
	if handle, err := pcap.OpenLive("wlp2s0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port " + os.Getenv("LISTEN_PORT")); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handleLivePacket(packet) // Do something with a packet here.
		}
	}
}
