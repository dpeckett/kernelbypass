//go:build linux

package kernelbypass

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/safchain/ethtool"
	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type NetworkInterfaceOptions struct {
	// NumQueues is the number of RX/TX queues to use for the interface.
	NumQueues int
	// AttachFlags are the flags which are passed when the XDP program is
	// attached to the network link, possible values include
	// unix.XDP_FLAGS_DRV_MODE, unix.XDP_FLAGS_HW_MODE, unix.XDP_FLAGS_SKB_MODE,
	// unix.XDP_FLAGS_UPDATE_IF_NOEXIST.
	AttachFlags uint32
	// SocketOpts are the options to use when creating XDP sockets.
	// These options can be used to set buffer sizes, queue sizes, etc.
	SocketOpts *xdp.SocketOptions
}

func getOptionsForDevice(link netlink.Link) (*NetworkInterfaceOptions, error) {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return nil, fmt.Errorf("failed to create ethtool handle: %w", err)
	}
	defer ethHandle.Close()

	driverName, err := ethHandle.DriverName(link.Attrs().Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get driver name: %w", err)
	}

	hardwareID, err := getHardwareID(link)
	if err != nil {
		return nil, fmt.Errorf("failed to get hardware ID: %w", err)
	}

	// TODO: match specific drivers or hardware IDs and return tuned configurations.

	slog.Debug("Using generic configuration for interface",
		slog.String("interface", link.Attrs().Name),
		slog.String("driver", driverName),
		slog.String("hardwareID", hardwareID),
	)

	return defaultOptions(link)
}

func defaultOptions(link netlink.Link) (*NetworkInterfaceOptions, error) {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return nil, fmt.Errorf("failed to create ethtool handle: %w", err)
	}
	defer ethHandle.Close()

	// Netlink returns the maximum number of RX and TX queues for the interface.
	// Not the current number of queues in use.
	channels, err := ethHandle.GetChannels(link.Attrs().Name)
	if err != nil && !errors.Is(err, unix.ENOTSUP) {
		return nil, fmt.Errorf("failed to get channels: %w", err)
	}

	numRxQueues := int(channels.RxCount)
	numTxQueues := int(channels.TxCount)

	if channels.CombinedCount > 0 {
		numRxQueues = int(channels.CombinedCount)
		numTxQueues = int(channels.CombinedCount)
	}

	if numRxQueues == 0 {
		numRxQueues = link.Attrs().NumRxQueues
	}
	if numTxQueues == 0 {
		numTxQueues = link.Attrs().NumTxQueues
	}

	if numRxQueues != numTxQueues {
		return nil, fmt.Errorf("asymmetric RX (%d) and TX (%d) queues are not supported", numRxQueues, numTxQueues)
	}

	return &NetworkInterfaceOptions{
		NumQueues:   numRxQueues,
		AttachFlags: xdp.DefaultXdpFlags,
	}, nil
}

func getHardwareID(link netlink.Link) (string, error) {
	devicePath := filepath.Join("/sys/class/net", link.Attrs().Name, "device")

	if _, err := os.Stat(devicePath); os.IsNotExist(err) {
		return "", nil
	}

	vendorPath := filepath.Join(devicePath, "vendor")
	deviceIDPath := filepath.Join(devicePath, "device")

	vendor, err := readSysfsFile(vendorPath)
	if err != nil {
		return "", fmt.Errorf("failed to read vendor ID: %w", err)
	}

	deviceID, err := readSysfsFile(deviceIDPath)
	if err != nil {
		return "", fmt.Errorf("failed to read device ID: %w", err)
	}

	return fmt.Sprintf("%s:%s", vendor, deviceID), nil
}

func readSysfsFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
