//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"math"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/dpeckett/kernelbypass"
	"github.com/dpeckett/kernelbypass/cmd/udpperf/internal/mac"
	"github.com/dpeckett/kernelbypass/cmd/udpperf/internal/permissions"
	"github.com/dpeckett/kernelbypass/filter"
	"github.com/dpeckett/kernelbypass/framing/udp"
	"github.com/urfave/cli/v2"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	flows = 64    // Number of flows to simulate (max is 16384)
	port  = 12345 // Port to listen for UDP datagrams
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	app := &cli.App{
		Name:  "udpperf",
		Usage: "A high-performance UDP datagram sender/receiver using kernel bypass techniques",
		Commands: []*cli.Command{
			{
				Name:  "sender",
				Usage: "Send UDP datagrams and report throughput",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "interface",
						Aliases:  []string{"i"},
						Usage:    "Network interface name to use",
						Required: true,
					},
					&cli.DurationFlag{
						Name:    "timeout",
						Aliases: []string{"t"},
						Usage:   "Timeout after which the sender will stop",
						Value:   10 * time.Second,
					},
					&cli.BoolFlag{
						Name:  "skip-checksum",
						Usage: "Skip UDP checksum calculation",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "realistic-sizes",
						Usage: "Use realistic packet sizes for UDP datagrams",
						Value: true,
					},
					&cli.StringFlag{
						Name:  "cpu-profile",
						Usage: "Path to write CPU profiling output",
					},
				},
				ArgsUsage: "<receiver ip>",
				Action:    runSender,
			},
			{
				Name:  "receiver",
				Usage: "Receive UDP datagrams and report throughput",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "interface",
						Aliases:  []string{"i"},
						Usage:    "Network interface name to use",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "skip-checksum",
						Usage: "Skip UDP checksum validation",
						Value: false,
					},
					&cli.StringFlag{
						Name:  "cpu-profile",
						Usage: "Path to write CPU profiling output",
					},
				},
				Action: runReceiver,
			},
		},
	}

	if err := app.Run(os.Args); err != nil && !(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		slog.Error("Application error", slog.Any("error", err))
		os.Exit(1)
	}
}

func runSender(c *cli.Context) error {
	if c.Args().Len() != 1 {
		return errors.New("sender requires exactly one argument: the receiver IP address")
	}
	receiverAddr := c.Args().First()

	name := c.String("interface")
	timeout := c.Duration("timeout")
	skipChecksum := c.Bool("skip-checksum")
	realisticSizes := c.Bool("realistic-sizes")

	if cpuProfilePath := c.String("cpu-profile"); cpuProfilePath != "" {
		f, err := os.Create(cpuProfilePath)
		if err != nil {
			return fmt.Errorf("failed to create CPU profile file: %w", err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	ctx, cancel := signal.NotifyContext(c.Context, os.Interrupt, os.Kill)
	defer cancel()

	isNetAdmin, err := permissions.IsNetAdmin()
	if err != nil {
		return fmt.Errorf("failed to check NET_ADMIN capability: %w", err)
	}
	if !isNetAdmin {
		return errors.New("this command requires the NET_ADMIN capability")
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	nlAddrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to get addresses for interface: %w", err)
	}

	var addrs []net.Addr
	for _, addr := range nlAddrs {
		if addr.IP == nil {
			continue
		}
		addrs = append(addrs, &net.UDPAddr{
			IP:   addr.IP,
			Port: port,
		})
	}

	ingressFilter, err := filter.Bind(addrs...)
	if err != nil {
		return fmt.Errorf("failed to create ingress filter: %w", err)
	}

	dstAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(receiverAddr, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("failed to resolve receiver address: %w", err)
	}

	dstMAC, err := mac.Resolve(ctx, link, addrs[0].(*net.UDPAddr), dstAddr.IP)
	if err != nil {
		return fmt.Errorf("failed to resolve destination MAC address: %w", err)
	}

	src := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(addrs[0].(*net.UDPAddr).IP.To4()),
		Port:     uint16(port),
		LinkAddr: tcpip.LinkAddress(link.Attrs().HardwareAddr),
	}

	dst := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(dstAddr.IP.To4()),
		Port:     uint16(port),
		LinkAddr: tcpip.LinkAddress(dstMAC),
	}

	payload := make([]byte, math.MaxUint16)
	_, _ = rand.Read(payload)

	h := &SendHandler{
		src:            src,
		dst:            dst,
		payload:        payload,
		skipChecksum:   skipChecksum,
		realisticSizes: realisticSizes,
	}

	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	go h.Report(ctx)

	nic, err := kernelbypass.Open(name, h, ingressFilter, nil)
	if err != nil {
		return fmt.Errorf("failed to open network interface: %w", err)
	}
	defer nic.Close()

	slog.Info("Starting sender",
		slog.String("interface", name),
		slog.String("receiver", dstAddr.String()))

	if err := nic.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

func runReceiver(c *cli.Context) error {
	name := c.String("interface")
	skipChecksum := c.Bool("skip-checksum")

	if cpuProfilePath := c.String("cpu-profile"); cpuProfilePath != "" {
		f, err := os.Create(cpuProfilePath)
		if err != nil {
			return fmt.Errorf("failed to create CPU profile file: %w", err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	ctx, cancel := signal.NotifyContext(c.Context, os.Interrupt, os.Kill)
	defer cancel()

	isNetAdmin, err := permissions.IsNetAdmin()
	if err != nil {
		return fmt.Errorf("failed to check NET_ADMIN capability: %w", err)
	}
	if !isNetAdmin {
		return errors.New("this command requires the NET_ADMIN capability")
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	nlAddrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to get addresses for interface: %w", err)
	}

	var addrs []net.Addr
	for _, addr := range nlAddrs {
		if addr.IP == nil {
			continue
		}
		addrs = append(addrs, &net.UDPAddr{
			IP:   addr.IP,
			Port: port,
		})
	}

	ingressFilter, err := filter.Bind(addrs...)
	if err != nil {
		return fmt.Errorf("failed to create ingress filter: %w", err)
	}

	h := &ReceiveHandler{
		skipChecksum: skipChecksum,
	}

	go h.Report(ctx)

	nic, err := kernelbypass.Open(name, h, ingressFilter, nil)
	if err != nil {
		return fmt.Errorf("failed to open network interface: %w", err)
	}
	defer nic.Close()

	slog.Info("Starting receiver",
		slog.String("interface", name),
		slog.String("address", addrs[0].String()),
	)

	if err := nic.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

// Realistic packet sizes you might encounter on the internet backbone.
var realisticPacketSizes = []int{
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // Common small packets (e.g., ACKs)
	576, 576, // Legacy default MTU for some protocols
	1432, 1432, 1432, 1432, 1432, 1432, // Full-size packets (max Ethernet frame size)
	128, 128, 128, // DNS or small application payloads
	512, 512, 512, // Mid-sized payloads (e.g., small downloads)
	1000, 1000, // FTP/HTTP small segment
	1432, 1432, 1432, // More full-size packets
	40, 40, // TCP SYN packets (minimal headers)
	64, 64, 64, // More ACKs or keepalives
	1432, 1432, 1432, 1432, // Full MTU packets
	900, 900, // Non-standard but plausible sizes
	200, 300, 400, // Application specific
	1432, 1432, 1432, // Ending with more full MTU packets
}

var _ kernelbypass.Handler = (*SendHandler)(nil)

type SendHandler struct {
	src            *tcpip.FullAddress
	dst            *tcpip.FullAddress
	payload        []byte
	skipChecksum   bool
	realisticSizes bool
	sentFrames     atomic.Int64
	sentBytes      atomic.Int64
}

func (h *SendHandler) ReceivedFrame(queueID int, frame []byte) {
	// Nop
}

func (h *SendHandler) NextFrame(queueID int, frame []byte) (int, error) {
	src := *h.src
	src.Port = uint16(49152 + int(new(maphash.Hash).Sum64()%flows))

	var datagramSize int
	if h.realisticSizes {
		datagramSize = realisticPacketSizes[new(maphash.Hash).Sum64()%uint64(len(realisticPacketSizes))]
	} else if src.Addr.Len() == net.IPv6len {
		datagramSize = 1432
	} else {
		datagramSize = 1458
	}

	copy(frame[:udp.PayloadOffsetIPv4], h.payload[:datagramSize])
	frameLen, err := udp.Encode(frame, &src, h.dst, datagramSize, h.skipChecksum)
	if err != nil {
		return 0, err
	}

	h.sentFrames.Add(1)
	h.sentBytes.Add(int64(frameLen))

	return frameLen, nil
}

func (h *SendHandler) Report(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sentPPS := h.sentFrames.Swap(0)
			sentMbit := float64(h.sentBytes.Swap(0)*8) / 1_000_000
			slog.Info("Sender throughput",
				slog.Float64("mbps", sentMbit), slog.Int64("pps", sentPPS))
		}
	}
}

var _ kernelbypass.Handler = (*ReceiveHandler)(nil)

type ReceiveHandler struct {
	skipChecksum   bool
	receivedFrames atomic.Int64
	receivedBytes  atomic.Int64
}

func (h *ReceiveHandler) ReceivedFrame(queueID int, frame []byte) {
	_, err := udp.Decode(frame, nil, h.skipChecksum)
	if err != nil {
		slog.Warn("Failed to decode UDP frame", slog.Any("error", err))
	}

	h.receivedFrames.Add(1)
	h.receivedBytes.Add(int64(len(frame)))
}

func (h *ReceiveHandler) NextFrame(queueID int, frame []byte) (int, error) {
	return 0, kernelbypass.ErrWouldBlock
}

func (h *ReceiveHandler) Report(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			receivedPPS := h.receivedFrames.Swap(0)
			receivedMbit := float64(h.receivedBytes.Swap(0)*8) / 1_000_000
			slog.Info("Receiver throughput",
				slog.Float64("mbps", receivedMbit),
				slog.Int64("pps", receivedPPS))
		}
	}
}
