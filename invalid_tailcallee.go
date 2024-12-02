// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang invalidTailcallee ./bpf/invalid-tailcallee.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -Wall

type resultInvalidTailcallee struct {
	oldKernel    bool
	haveFreplace bool

	fixedInfiniteLoopCausedByFreplace   bool
	issueInvalidTailcallee              bool
	issuePanicCausedByFreplaceNotExists bool
}

func detectInvalidTailcallee() (resultInvalidTailcallee, error) {
	var res resultInvalidTailcallee

	spec, err := loadInvalidTailcallee()
	if err != nil {
		return res, fmt.Errorf("failed to load bpf spec: %w", err)
	}

	prog, err := ebpf.NewProgram(spec.Programs["entry"])
	if err != nil {
		res.oldKernel = true
		return res, nil
	}
	defer prog.Close()

	tcProg, err := ebpf.NewProgram(spec.Programs["tc_entry"])
	if err != nil {
		return res, nil
	}
	defer tcProg.Close()

	delete(spec.Programs, "entry")
	delete(spec.Programs, "tc_entry")
	spec.Programs["freplace_entry"].AttachTarget = prog
	spec.Programs["freplace_entry"].AttachTo = "xdp_subprog"
	spec.Programs["freplace_tailcallee"].AttachTarget = prog
	spec.Programs["freplace_tailcallee"].AttachTo = "xdp_subprog"
	spec.Programs["freplace_tailcallee_invalid"].AttachTarget = tcProg
	spec.Programs["freplace_tailcallee_invalid"].AttachTo = "tc_subprog"

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return res, nil
	}
	defer coll.Close()
	res.haveFreplace = true

	progArray := coll.Maps["jmp_table"]
	err = progArray.Put(uint32(0), coll.Programs["freplace_tailcallee"])
	if err != nil {
		if errors.Is(err, unix.EINVAL) {
			res.fixedInfiniteLoopCausedByFreplace = true
		} else {
			return res, fmt.Errorf("failed to put freplace_tailcallee into jmp table: %w", err)
		}
	}

	err = progArray.Put(uint32(1), prog)
	if err != nil && errors.Is(err, unix.EINVAL) {
		res.issuePanicCausedByFreplaceNotExists = true
	}

	err = progArray.Put(uint32(1), coll.Programs["freplace_tailcallee_invalid"])
	if err != nil {
		if errors.Is(err, unix.EINVAL) {
			// Issue has been fixed.
			return res, nil
		}
		return res, fmt.Errorf("failed to put freplace_tailcallee_invalid into jmp table: %w", err)
	}

	res.issueInvalidTailcallee = true
	return res, nil
}
