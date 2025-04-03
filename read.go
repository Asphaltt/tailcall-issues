// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang read ./bpf/read.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -Wall

const readMax = 1024

func readKernel(addr uint64, size uint32) ([]byte, error) {
	if size > readMax {
		return nil, fmt.Errorf("size %d is larger than limit %d", size, readMax)
	}

	spec, err := loadRead()
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf spec: %w", err)
	}

	if err := spec.Variables["__addr"].Set(addr); err != nil {
		return nil, fmt.Errorf("failed to set __addr: %w", err)
	}
	if err := spec.Variables["__size"].Set(size); err != nil {
		return nil, fmt.Errorf("failed to set __size: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogDisabled: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["read"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	defer l.Close()

	nanosleep()

	var run bool
	if err := coll.Variables["run"].Get(&run); err != nil {
		return nil, fmt.Errorf("failed to get run: %w", err)
	}
	if !run {
		return nil, errors.New("reading kernel was not triggered")
	}

	var buff [readMax]byte
	if err := coll.Variables["buff"].Get(&buff); err != nil {
		return nil, fmt.Errorf("failed to get buff: %w", err)
	}

	return buff[:size], nil
}
