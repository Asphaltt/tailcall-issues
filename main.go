// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import flag "github.com/spf13/pflag"

var waitToExit bool

func main() {
	var checkInvalidOffset bool
	var bpfProgID uint32
	flag.BoolVar(&waitToExit, "wait", false, "Wait to exit")
	flag.BoolVar(&checkInvalidOffset, "check-invalid-offset", false, "Check invalid offset issue")
	flag.Uint32Var(&bpfProgID, "prog", 0, "BPF program ID")
	flag.Parse()

	if checkInvalidOffset {
		checkIssueInvalidOffset(bpfProgID)
	}
}
