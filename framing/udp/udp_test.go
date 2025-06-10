package udp_test

import (
	"net"
	"testing"

	"github.com/dpeckett/kernelbypass/framing/udp"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecode_IPv4(t *testing.T) {
	const frameSize = 1500

	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	srcAddr := &net.UDPAddr{
		IP:   net.IPv4(192, 168, 1, 1),
		Port: 12345,
	}
	dstAddr := &net.UDPAddr{
		IP:   net.IPv4(192, 168, 1, 2),
		Port: 54321,
	}

	payload := []byte("Hello, UDP over Ethernet!")

	t.Run("Valid", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv4:], payload)

		n, err := udp.Encode(frame, srcMAC, dstMAC, srcAddr, dstAddr, len(payload), false)
		require.NoError(t, err)

		// Pass the encoded frame to Decode
		decodedAddr, decodedPayload, err := udp.Decode(frame[:n], false)
		require.NoError(t, err)
		require.Equal(t, srcAddr.IP.String(), decodedAddr.IP.String())
		require.Equal(t, srcAddr.Port, decodedAddr.Port)
		require.Equal(t, payload, decodedPayload)
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv4:], payload)

		n, err := udp.Encode(frame, srcMAC, dstMAC, srcAddr, dstAddr, len(payload), false)
		require.NoError(t, err)

		// Corrupt the first byte of the UDP payload
		udpStart := header.EthernetMinimumSize + header.IPv4MinimumSize
		payloadOffset := udpStart + header.UDPMinimumSize
		frame[payloadOffset] ^= 0xFF

		_, _, err = udp.Decode(frame[:n], false)
		require.Error(t, err)
	})
}

func TestEncodeDecode_IPv6(t *testing.T) {
	const frameSize = 1500

	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x04}

	srcAddr := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 12345,
	}
	dstAddr := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::2"),
		Port: 54321,
	}

	payload := []byte("Hello, UDP over Ethernet!")

	t.Run("Valid", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv6:], payload)

		n, err := udp.Encode(frame, srcMAC, dstMAC, srcAddr, dstAddr, len(payload), false)
		require.NoError(t, err)

		decodedAddr, decodedPayload, err := udp.Decode(frame[:n], false)
		require.NoError(t, err)
		require.Equal(t, srcAddr.IP.String(), decodedAddr.IP.String())
		require.Equal(t, srcAddr.Port, decodedAddr.Port)
		require.Equal(t, payload, decodedPayload)
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv6:], payload)
		frame = frame[:udp.PayloadOffsetIPv6+len(payload)]

		n, err := udp.Encode(frame, srcMAC, dstMAC, srcAddr, dstAddr, len(payload), false)
		require.NoError(t, err)

		// Corrupt the first byte of the UDP payload
		udpStart := header.EthernetMinimumSize + header.IPv6MinimumSize
		payloadOffset := udpStart + header.UDPMinimumSize
		frame[payloadOffset] ^= 0xFF

		_, _, err = udp.Decode(frame[:n], false)
		require.Error(t, err)
	})
}
