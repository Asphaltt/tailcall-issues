// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/Asphaltt/tailcall-issues/internal/assert"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang loop ./issue.c -- -g -D__TARGET_ARCH_x86 -I../../bpf/headers -Wall

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock limit: %v")

	spec, err := loadLoop()
	assert.NoErr(err, "Failed to load bpf spec: %v")
	delete(spec.Programs, "fexit_subprog")

	coll, err := ebpf.NewCollection(spec)
	assert.NoErr(err, "Failed to create bpf collection: %v")
	defer coll.Close()

	prog := coll.Programs["k_tcp_connect"]
	err = coll.Maps["jmp_table"].Put(uint32(0), prog)
	assert.NoErr(err, "Failed to put jmp_table: %v")
	log.Print("Put jmp_table with k_tcp_connect")

	spec, err = loadLoop()
	assert.NoErr(err, "Failed to load bpf spec: %v")
	delete(spec.Programs, "k_tcp_connect")
	delete(spec.Maps, "jmp_table")
	fexitProgSpec := spec.Programs["fexit_subprog"]
	fexitProgSpec.AttachTarget = prog
	fexitProgSpec.AttachTo = "subprog"

	coll, err = ebpf.NewCollection(spec)
	assert.NoErr(err, "Failed to create bpf collection: %v")
	defer coll.Close()

	fexit, err := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs["fexit_subprog"],
		AttachType: ebpf.AttachTraceFExit,
	})
	assert.NoErr(err, "Failed to attach fexit: %v")
	defer fexit.Close()
	log.Print("Attached fexit to subprog")

	kp, err := link.Kprobe("tcp_connect", prog, nil)
	assert.NoErr(err, "Failed to attach kprobe: %v")
	defer kp.Close()
	log.Print("Attached kprobe to tcp_connect")

	log.Print("Press Ctrl+C to exit")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()
}
