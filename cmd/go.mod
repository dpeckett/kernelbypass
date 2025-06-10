module github.com/dpeckett/kernelbypass/cmd

go 1.24.3

replace github.com/dpeckett/kernelbypass => ../

require (
	github.com/avast/retry-go/v4 v4.6.1
	github.com/dpeckett/kernelbypass v0.0.0-00010101000000-000000000000
	github.com/urfave/cli/v2 v2.27.6
	github.com/vishvananda/netlink v1.3.1
)

require (
	github.com/cilium/ebpf v0.18.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.5 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/safchain/ethtool v0.6.1 // indirect
	github.com/slavc/xdp v0.3.4 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	gvisor.dev/gvisor v0.0.0-20250606001031-fa4c4dd86b43 // indirect
)
