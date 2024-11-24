module github.com/Asphaltt/tailcall-issues

go 1.23.3

require (
	github.com/cilium/ebpf v0.16.0
	github.com/knightsc/gapstone v4.0.1+incompatible
	github.com/spf13/pflag v1.0.5
)

require golang.org/x/sys v0.20.0 // indirect

replace github.com/cilium/ebpf v0.16.0 => github.com/Asphaltt/ebpf v0.0.0-20241102052356-d5a4c9e8b9c2
