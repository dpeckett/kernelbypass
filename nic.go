//go:build linux

package kernelbypass

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

// ErrWouldBlock should be returned by Handler.NextFrame when no frame is
// available to send.
var ErrWouldBlock = errors.New("would block")

// Handler is an interface that defines methods for processing frames in a
// kernel-bypass network interface using XDP. The handler should not block.
type Handler interface {
	// ReceivedFrame is called when a new frame is received.
	ReceivedFrame(queueID int, frame []byte)
	// NextFrame is called when a new frame buffer becomes available.
	// It returns the number of bytes written to the frame buffer, or an error.
	// If you don't want to send a frame, return ErrWouldBlock.
	NextFrame(queueID int, frame []byte) (int, error)
}

// NetworkInterface represents a network interface that uses XDP for
// high-performance kernel-bypass packet processing.
type NetworkInterface struct {
	handler       Handler
	link          netlink.Link
	ingressFilter *xdp.Program
	xsks          []*xdp.Socket
}

// Open creates a new NetworkInterface for the provided interface name and options.
func Open(name string, handler Handler, ingressFilter *xdp.Program, opts *NetworkInterfaceOptions) (*NetworkInterface, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	if opts == nil {
		opts, err = getOptionsForDevice(link)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface configuration: %w", err)
		}
	}

	if ingressFilter != nil {
		// Attach the XDP program to the interface.
		if err := netlink.LinkSetXdpFdWithFlags(link, ingressFilter.Program.FD(), int(xdp.DefaultXdpFlags)); err != nil {
			return nil, fmt.Errorf("failed to attach XDP program: %w", err)
		}
	}

	var xsks []*xdp.Socket
	for queueID := 0; queueID < opts.NumQueues; queueID++ {
		xsk, err := xdp.NewSocket(link.Attrs().Index, queueID, opts.SocketOpts)
		if err != nil {
			if ingressFilter != nil {
				_ = ingressFilter.Detach(link.Attrs().Index)
			}
			for _, xsk := range xsks {
				_ = xsk.Close()
			}
			return nil, fmt.Errorf("failed to create XDP socket: %w", err)
		}

		xsks = append(xsks, xsk)

		if err := ingressFilter.Register(queueID, xsk.FD()); err != nil {
			if ingressFilter != nil {
				_ = ingressFilter.Detach(link.Attrs().Index)
			}
			for _, xsk := range xsks {
				_ = xsk.Close()
			}
			return nil, fmt.Errorf("failed to register socket with XDP filter: %w", err)
		}
	}

	return &NetworkInterface{
		handler:       handler,
		link:          link,
		ingressFilter: ingressFilter,
		xsks:          xsks,
	}, nil
}

// Close closes the NetworkInterface and releases all resources.
func (nic *NetworkInterface) Close() error {
	if nic.ingressFilter != nil {
		if err := nic.ingressFilter.Detach(nic.link.Attrs().Index); err != nil {
			return fmt.Errorf("failed to detach XDP filter: %w", err)
		}
	}

	for _, xsk := range nic.xsks {
		if err := xsk.Close(); err != nil {
			return fmt.Errorf("failed to close XDP socket: %w", err)
		}
	}

	return nil
}

func (nic *NetworkInterface) Start(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	for queueID, xsk := range nic.xsks {
		g.Go(func() error {
			return nic.processFrames(ctx, queueID, xsk)
		})
	}

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

func (nic *NetworkInterface) processFrames(ctx context.Context, queueID int, xsk *xdp.Socket) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if n := xsk.NumFreeFillSlots(); n > 0 {
			xsk.Fill(xsk.GetDescs(n, true))
		}

		numReceived, _, err := pollWithContext(ctx, xsk)
		if err != nil {
			return fmt.Errorf("poll error: %w", err)
		}

		if numReceived > 0 {
			rxDescs := xsk.Receive(numReceived)
			for _, desc := range rxDescs {
				frame := xsk.GetFrame(desc)
				nic.handler.ReceivedFrame(queueID, frame)
			}
		}

		txDescs := xsk.GetDescs(xsk.NumFreeTxSlots(), false)
		if len(txDescs) == 0 {
			continue
		}

		var populatedDescs int
		for i := range txDescs {
			frame := xsk.GetFrame(txDescs[i])

			n, err := nic.handler.NextFrame(queueID, frame)
			if err != nil {
				if !errors.Is(err, ErrWouldBlock) {
					slog.Warn("NextFrame failed", slog.Any("error", err))
				}
				break
			}

			txDescs[i].Len = uint32(n)
			populatedDescs++
		}

		if populatedDescs > 0 {
			xsk.Transmit(txDescs[:populatedDescs])
		}
	}
}

func pollWithContext(ctx context.Context, xsk *xdp.Socket) (numReceived int, numCompleted int, err error) {
	for {
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		default:
			numReceived, numCompleted, err := xsk.Poll(100)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) {
					continue
				}
				return 0, 0, err
			}
			return numReceived, numCompleted, nil
		}
	}
}
