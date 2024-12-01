// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang subprog ./bpf/bpf2bpf.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -Wall

func detectBpf2bpf() (bool, error) {
	var objs subprogObjects
	err := loadSubprogObjects(&objs, nil)
	if err != nil {
		if errors.Is(err, unix.EINVAL) {
			return false, nil
		}
		return false, err
	}
	defer objs.Close()

	return true, nil
}
