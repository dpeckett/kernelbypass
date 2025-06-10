package mac

import (
	"fmt"
	"math"
	"net"

	"github.com/avast/retry-go/v4"
	"github.com/vishvananda/netlink"
)

// Resolve resolves the MAC address for the given IP address using the provided link.
func Resolve(link netlink.Link, localAddr *net.UDPAddr, ip net.IP) (net.HardwareAddr, error) {
	mac, err := searchNeighborList(link, ip)
	if err == nil {
		return mac, nil
	}

	srcAddr := &net.UDPAddr{
		IP: localAddr.IP,
	}

	remoteAddr := &net.UDPAddr{
		IP:   ip,
		Port: math.MaxUint16,
	}

	var dstMAC net.HardwareAddr
	err = retry.Do(func() error {
		// Trigger OS neighbor resolution by sending a dummy packet.
		conn, err := net.DialUDP("udp", srcAddr, remoteAddr)
		if err != nil {
			return fmt.Errorf("failed to trigger ARP resolution: %w", err)
		}
		defer conn.Close()

		if _, err := conn.Write(nil); err != nil {
			return fmt.Errorf("failed to write to UDP: %w", err)
		}

		dstMAC, err = searchNeighborList(link, ip)
		if err != nil {
			return err
		}

		return nil
	}, retry.Attempts(3), retry.DelayType(retry.BackOffDelay), retry.MaxDelay(50))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve MAC address for %s: %w", ip, err)
	}

	return dstMAC, nil
}

func searchNeighborList(link netlink.Link, ip net.IP) (net.HardwareAddr, error) {
	var family int
	if ip.To4() != nil {
		family = netlink.FAMILY_V4
	} else {
		family = netlink.FAMILY_V6
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, family)
	if err != nil {
		return nil, fmt.Errorf("failed to list neighbors: %w", err)
	}

	for _, n := range neighs {
		if n.IP.Equal(ip) && n.HardwareAddr != nil &&
			(n.State == netlink.NUD_REACHABLE || n.State == netlink.NUD_STALE || n.State == netlink.NUD_DELAY) {
			return n.HardwareAddr, nil
		}
	}

	return nil, fmt.Errorf("MAC not yet resolved for %s", ip)
}
