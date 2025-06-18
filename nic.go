//go:build linux

package kernelbypass

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

// Handler is an interface that defines methods for processing frames in a
// kernel-bypass network interface using XDP. The handler should not block.
type Handler interface {
	// BatchSize returns the maximum number of frames that can be processed
	// in a single batch.
	BatchSize() int
	// Receive is called when new frames are received.
	Receive(queueID int, frames [][]byte)
	// Transmit is called to prepare frames for transmission.
	// It returns the number of frames that were successfully prepared for
	// transmission. The frames should be filled with the data to be sent.
	// The lengths slice should be filled with the lengths of each frame.
	Transmit(queueID int, frames [][]byte, lengths []int) int
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

		if ingressFilter != nil {
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

// NumQueues returns the number of queues configured for this network interface.
func (nic *NetworkInterface) NumQueues() int {
	return len(nic.xsks)
}

func (nic *NetworkInterface) processFrames(ctx context.Context, queueID int, xsk *xdp.Socket) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	batchSize := nic.handler.BatchSize()
	frames := make([][]byte, batchSize)
	lengths := make([]int, batchSize)

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

			for i := 0; i < len(rxDescs); i += batchSize {
				end := i + batchSize
				if end > len(rxDescs) {
					end = len(rxDescs)
				}

				batch := rxDescs[i:end]
				for j := range batch {
					frames[j] = xsk.GetFrame(batch[j])
				}

				nic.handler.Receive(queueID, frames[:len(batch)])
			}
		}

		txDescs := xsk.GetDescs(xsk.NumFreeTxSlots(), false)
		if len(txDescs) == 0 {
			continue
		}

		for i := 0; i < len(txDescs); i += batchSize {
			end := i + batchSize
			if end > len(txDescs) {
				end = len(txDescs)
			}

			batchDescs := txDescs[i:end]
			for j := range batchDescs {
				frames[j] = xsk.GetFrame(batchDescs[j])
			}

			lengths = lengths[:len(batchDescs)]
			numToTransmit := nic.handler.Transmit(queueID, frames[:len(batchDescs)], lengths)

			for j, length := range lengths[:numToTransmit] {
				batchDescs[j].Len = uint32(length)
			}

			if numToTransmit > 0 {
				xsk.Transmit(batchDescs[:numToTransmit])
			} else {
				break
			}
		}
	}
}

func pollWithContext(ctx context.Context, xsk *xdp.Socket) (numReceived int, numCompleted int, err error) {
	for {
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		default:
			numReceived, numCompleted, err := xsk.Poll(1)
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
