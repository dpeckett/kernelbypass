//go:build linux

package kernelbypass_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sync/errgroup"
)

const (
	hostIf     = "veth0"
	nsIf       = "veth1"
	hostIP     = "10.0.0.1/24"
	peerIP     = "10.0.0.2/24"
	testNsName = "kernelbypass-testns"
)

func TestNetworkInterface(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "kernelbypass-demo")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = filepath.Join("cmd")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Run())

	originalNS, err := netns.Get()
	require.NoError(t, err)

	_ = netns.DeleteNamed(testNsName)
	testNS, err := netns.NewNamed(testNsName)
	require.NoError(t, err)
	require.NoError(t, netns.Set(originalNS))

	// Setup veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostIf,
		},
		PeerName: nsIf,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("failed to add veth pair: %v", err)
	}
	t.Cleanup(func() {
		_ = netlink.LinkDel(veth)
	})

	// Move peer to new namespace
	peer, err := netlink.LinkByName(nsIf)
	require.NoError(t, err)

	require.NoError(t, netlink.LinkSetNsFd(peer, int(testNS)))

	// Configure host side
	hostLink, err := netlink.LinkByName(hostIf)
	require.NoError(t, err)

	addr, err := netlink.ParseAddr(hostIP)
	require.NoError(t, err)

	err = netlink.AddrAdd(hostLink, addr)
	require.NoError(t, err)

	err = netlink.LinkSetUp(hostLink)
	require.NoError(t, err)

	// Configure peer inside new namespace
	require.NoError(t, doInNamespace(testNS, func() error {
		nsLink, err := netlink.LinkByName(nsIf)
		if err != nil {
			return err
		}
		peerAddr, err := netlink.ParseAddr(peerIP)
		if err != nil {
			return err
		}

		if err := netlink.AddrAdd(nsLink, peerAddr); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(nsLink); err != nil {
			return err
		}

		return nil
	}))

	g, ctx := errgroup.WithContext(t.Context())

	g.Go(func() error {
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", testNsName, binPath, "receiver", "--interface", nsIf)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	})

	g.Go(func() error {
		cmd := exec.CommandContext(ctx, binPath, "sender", "--interface", hostIf, "10.0.0.2")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}

		return context.Canceled // signal completion
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("error during test execution: %v", err)
	}
}

func doInNamespace(ns netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	originalNS, err := netns.Get()
	if err != nil {
		return err
	}
	defer func() {
		_ = netns.Set(originalNS)
	}()

	if err := netns.Set(ns); err != nil {
		return err
	}

	return fn()
}
