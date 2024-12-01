module github.com/Asphaltt/tailcall-issues

go 1.23.3

require (
	github.com/cilium/ebpf v0.16.0
	github.com/fatih/color v1.18.0
	github.com/knightsc/gapstone v4.0.1+incompatible
	github.com/spf13/pflag v1.0.5
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.25.0
)

replace github.com/cilium/ebpf v0.16.0 => github.com/Asphaltt/ebpf v0.0.0-20241102052356-d5a4c9e8b9c2
