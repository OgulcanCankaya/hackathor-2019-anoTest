package main

import (
	"encoding/json"
	"fmt"
	"strings"

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
}

var Packets []httpPacket

func handlePacket(packet gopacket.Packet) {
	//packet_d := new (packet_data)
	if packet.ApplicationLayer() != nil {
		payload := packet.ApplicationLayer().Payload()
		str := string(payload[:])

		if strings.Contains(str, "HTTP/1.1") {

			fmt.Println("==========HTTP VAR===========")
			fmt.Println(str)
			fmt.Println("=================SON=================")

			//println(str)

			var HttpPacket httpPacket

			str_arr := strings.Split(str, "\n")

			first_line := strings.Split(str_arr[0], " ")

			HttpPacket.Method = first_line[0]
			HttpPacket.Dir = first_line[1]
			HttpPacket.HTTPVersion = first_line[2]
			//fmt.Println(HttpPacket.Headers)

			// for _, i := range str_arr {
			// 	if len(i) > 1 {
			// 		fmt.Println("---" + i)
			// 	} else {
			// 		fmt.Println("gardaş burda bi sıkkıntı")
			// 	}
			// }

			for _, header := range str_arr[1 : strings.Count(str, ": ")+1] {
				if len(header) > 1 {

					// fmt.Println("Header: ", header)

					header_arr := strings.Split(header, ": ")
					//fmt.Println("********")
					//println(len(header_arr))
					//println((header_arr[0]))
					//println("-",header_arr[1])

					// for _, i := range header_arr {
					// 	// fmt.Println("i: " + i)
					// 	fmt.Println("# " + i)
					// }

					// fmt.Println("----")
					// fmt.Println(header_arr[0])
					// fmt.Println(header_arr[1])
					// fmt.Println("----")

					var headera Header

					headera.Key = header_arr[0]
					headera.Value = header_arr[1]

					// fmt.Println("Headera: ", headera)

					HttpPacket.Headers = append(HttpPacket.Headers, headera)
				}
			}

			Packets = append(Packets, HttpPacket)
		}

	}

}

func main() {
	if handle, err := pcap.OpenOffline("/home/batuberk/go/src/github.com/batuberksahin/hackathor/hackathor/ruleEngine/main.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			handlePacket(packet) // Do something with a packet here.
		}
	}

	fmt.Println("bitiş :D")

	data, _ := json.Marshal(&Packets)
	fmt.Println(string(data))
}
