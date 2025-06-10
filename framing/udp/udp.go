package udp

import (
	"errors"
	"math"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	PayloadOffsetIPv4 = header.EthernetMinimumSize + header.IPv4MinimumSize + header.UDPMinimumSize
	PayloadOffsetIPv6 = header.EthernetMinimumSize + header.IPv6MinimumSize + header.UDPMinimumSize
)

// Decode extracts the source address and payload from a UDP ethernet frame.
func Decode(frame []byte, skipChecksumValidation bool) (*net.UDPAddr, []byte, error) {
	var (
		udp     header.UDP
		srcAddr tcpip.Address
		dstAddr tcpip.Address
	)

	if len(frame) < header.EthernetMinimumSize {
		return nil, nil, errors.New("frame too short")
	}

	eth := header.Ethernet(frame)
	ethType := eth.Type()

	switch ethType {
	case header.IPv4ProtocolNumber:
		ip := header.IPv4(frame[header.EthernetMinimumSize:])
		if !ip.IsValid(len(ip)) || ip.Protocol() != uint8(header.UDPProtocolNumber) {
			return nil, nil, errors.New("not a valid IPv4 UDP packet")
		}
		srcAddr = ip.SourceAddress()
		dstAddr = ip.DestinationAddress()
		udp = header.UDP(ip.Payload())

	case header.IPv6ProtocolNumber:
		ip := header.IPv6(frame[header.EthernetMinimumSize:])
		if !ip.IsValid(len(ip)) || ip.TransportProtocol() != header.UDPProtocolNumber {
			return nil, nil, errors.New("not a valid IPv6 UDP packet")
		}
		srcAddr = ip.SourceAddress()
		dstAddr = ip.DestinationAddress()
		udp = header.UDP(ip.Payload())

	default:
		return nil, nil, errors.New("unsupported ethertype")
	}

	lengthValid, csumValid := header.UDPValid(
		udp,
		func() uint16 { return checksum.Checksum(udp.Payload(), 0) },
		uint16(len(udp.Payload())),
		tcpip.NetworkProtocolNumber(header.UDPProtocolNumber),
		srcAddr,
		dstAddr,
		skipChecksumValidation,
	)
	if !lengthValid || !csumValid {
		return nil, nil, errors.New("invalid UDP checksum or length")
	}

	return &net.UDPAddr{
		IP:   net.IP(srcAddr.AsSlice()),
		Port: int(udp.SourcePort()),
	}, udp.Payload(), nil
}

// Encode constructs a UDP ethernet frame with the given parameters.
// It assumes that the payload is already in the frame buffer at the correct
// offset.
func Encode(frame []byte, srcMAC, dstMAC net.HardwareAddr, srcAddr, dstAddr *net.UDPAddr, payloadLength int, skipChecksumCalculation bool) (int, error) {
	var offset int

	isIPv6 := srcAddr.IP.To4() == nil

	eth := header.Ethernet(frame[offset:])
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC),
		DstAddr: tcpip.LinkAddress(dstMAC),
		Type: func() tcpip.NetworkProtocolNumber {
			if isIPv6 {
				return header.IPv6ProtocolNumber
			}
			return header.IPv4ProtocolNumber
		}(),
	})
	offset += header.EthernetMinimumSize

	udpPayloadLength := header.UDPMinimumSize + payloadLength
	var srcAddrNetstack, dstAddrNetstack tcpip.Address

	if isIPv6 {
		srcAddrNetstack = tcpip.AddrFromSlice(srcAddr.IP.To16())
		dstAddrNetstack = tcpip.AddrFromSlice(dstAddr.IP.To16())

		ip := header.IPv6(frame[offset:])
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(udpPayloadLength),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           srcAddrNetstack,
			DstAddr:           dstAddrNetstack,
		})
		offset += header.IPv6MinimumSize
	} else {
		srcAddrNetstack = tcpip.AddrFromSlice(srcAddr.IP.To4())
		dstAddrNetstack = tcpip.AddrFromSlice(dstAddr.IP.To4())

		ip := header.IPv4(frame[offset:])
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + udpPayloadLength),
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     srcAddrNetstack,
			DstAddr:     dstAddrNetstack,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		offset += header.IPv4MinimumSize
	}

	udp := header.UDP(frame[offset:])
	udp.Encode(&header.UDPFields{
		SrcPort: uint16(srcAddr.Port),
		DstPort: uint16(dstAddr.Port),
		Length:  uint16(udpPayloadLength),
	})
	offset += header.UDPMinimumSize

	if !skipChecksumCalculation {
		csum := udp.CalculateChecksum(checksum.Combine(
			header.PseudoHeaderChecksum(
				header.UDPProtocolNumber,
				srcAddrNetstack,
				dstAddrNetstack,
				uint16(udpPayloadLength),
			),
			checksum.Checksum(frame[offset:offset+payloadLength], 0),
		))
		if csum != math.MaxUint16 {
			csum = ^csum
		}
		udp.SetChecksum(csum)
	}

	return offset + payloadLength, nil
}
