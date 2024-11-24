// Copyright 2024 Leon Hwang.
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
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang invalid ./bpf/invalid-offset.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -Wall

func checkIssueInvalidOffset(progID uint32) {
	var objs invalidObjects
	err := loadInvalidObjects(&objs, nil)
	assert.NoVerifierErr(err, "Failed to load invalid-offset bpf objects: %v")
	defer objs.Close()

	err = objs.JmpTable.Put(uint32(0), objs.Tailcallee)
	assert.NoErr(err, "Failed to put tailcallee into jmp table: %v")

	info, err := newBpfProgInfo(objs.Entry)
	assert.NoErr(err, "Failed to get program info: %v")

	if info.issueInvalidOffset {
		log.Printf("Current kernel has invalid offset issue")
	} else {
		log.Printf("Current kernel does not have invalid offset issue")
	}

	l, err := link.Kprobe("tcp_connect", objs.Entry, nil)
	assert.NoErr(err, "Failed to attach kprobe: %v")
	defer l.Close()

	if progID != 0 {
		prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
		assert.NoErr(err, "Failed to get program from ID: %v")
		defer prog.Close()

		info, err := newBpfProgInfo(prog)
		assert.NoErr(err, "Failed to get program info: %v")
		if info.issueInvalidOffset {
			log.Printf("BPF program (id=%d name=%s) has invalid offset issue", progID, info.name)
		} else {
			log.Printf("BPF program (id=%d name=%s) does not have invalid offset issue", progID, info.name)
		}

		return
	}

	if !waitToExit {
		return
	}

	log.Printf("Ctrl+C to stop ..")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()
}
