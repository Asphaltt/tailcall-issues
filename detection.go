// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"

	"github.com/Asphaltt/tailcall-issues/internal/assert"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/fatih/color"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang loop ./bpf/infinite-loop-caused-by-trampoline.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -Wall

func detectIssues() {
	invalidTailcallee, err := detectInvalidTailcallee()
	assert.NoErr(err, "Failed to detect invalid tailcallee: %v")

	haveFreplace := invalidTailcallee.haveFreplace

	haveBpf2bpf, err := detectBpf2bpf()
	haveTailcallInBpf2bpf := false

	var info *bpfProgInfo

	if haveBpf2bpf {
		var objs invalidObjects
		err = loadInvalidObjects(&objs, nil)
		if err == nil || !strings.Contains(err.Error(), "tail_calls are not allowed in programs with bpf-to-bpf calls") {
			assert.NoVerifierErr(err, "Failed to load invalid-offset bpf objects: %v")
			defer objs.Close()

			// Ignore the error if the kernel does not support tail calls in
			// bpf-to-bpf programs.
			haveTailcallInBpf2bpf = true

			spec, err := loadLoop()
			assert.NoErr(err, "Failed to load bpf spec: %v")

			spec.Programs["fentry_fn"].AttachTarget = objs.Entry
			spec.Programs["fentry_fn"].AttachTo = "entry"

			coll, err := ebpf.NewCollection(spec)
			assert.NoVerifierErr(err, "Failed to create bpf collection: %v")
			defer coll.Close()

			l, err := link.AttachTracing(link.TracingOptions{
				Program:    coll.Programs["fentry_fn"],
				AttachType: ebpf.AttachTraceFEntry,
			})
			assert.NoErr(err, "Failed to attach tracing: %v")
			defer l.Close()

			info, err = newBpfProgInfo(objs.Entry, true)
			assert.NoErr(err, "Failed to prepare program info: %v")
		}
	}

	var sb strings.Builder

	color.New(color.FgYellow, color.Bold).Fprint(&sb, "tailcall issues:\n\n")

	printIssueDetails(&sb, &tailcallIssueInvalidTailcallee)
	fmt.Fprintln(&sb)
	printIssueDetails(&sb, &tailcallIssueInvalidOffset)
	fmt.Fprintln(&sb)
	printIssueDetails(&sb, &tailcallIssueInfiniteLoopCausedByTrampoline)
	fmt.Fprintln(&sb)
	printIssueDetails(&sb, &tailcallIssueHierarchy)
	fmt.Fprintln(&sb)
	printIssueDetails(&sb, &tailcallIssuePanicCausedByUpdatingAttachedFreplaceProgToProgArray)
	fmt.Fprintln(&sb)
	printIssueDetails(&sb, &tailcallIssueInfiniteLoopCausedByFreplace)
	fmt.Fprintln(&sb)

	fmt.Fprintln(&sb)

	if invalidTailcallee.oldKernel {
		if !haveTailcallInBpf2bpf {
			color.New(color.FgYellow).Fprintf(&sb, "Current kernel is too old to support tailcalls in bpf2bpf programs.\n")
		}

		color.New(color.FgYellow, color.Bold).Fprint(&sb, "Cannot run bpf2bpf with go-ebpf on current kernel.\n")
		fmt.Println(sb.String())
		return
	}

	color.New(color.FgGreen, color.Bold).Fprint(&sb, "detection results:\n\n")

	issue := &tailcallIssueInvalidTailcallee
	if !haveFreplace {
		printIssueState(&sb, issue, issueStateNotExists, color.New(color.FgGreen))
	} else if invalidTailcallee.issueInvalidTailcallee {
		printIssueState(&sb, issue, issueStateNotFixed, color.New(color.FgRed, color.Bold))
	} else {
		printIssueState(&sb, issue, issueStateFixed, color.New(color.FgGreen, color.Bold))
	}
	fmt.Fprintln(&sb)

	issue = &tailcallIssueInvalidOffset
	if !haveBpf2bpf {
		printIssueState(&sb, issue, issueStateNotExists, color.New(color.FgGreen))
	} else if info.issueInvalidOffset {
		printIssueState(&sb, issue, issueStateNotFixed, color.New(color.FgRed, color.Bold))
	} else {
		printIssueState(&sb, issue, issueStateFixed, color.New(color.FgGreen, color.Bold))
	}
	fmt.Fprintln(&sb)

	issue = &tailcallIssueInfiniteLoopCausedByTrampoline
	if !haveBpf2bpf {
		printIssueState(&sb, issue, issueStateNotExists, color.New(color.FgGreen))
	} else if info.failedDetectInfiniteLoopCausedByTrampoline {
		printIssueState(&sb, issue, issueStateCannotDetect, color.New(color.FgYellow))
	} else if info.fixedTailcallInfiniteLoopCausedByTrampoline {
		printIssueState(&sb, issue, issueStateFixed, color.New(color.FgGreen, color.Bold))
	} else {
		printIssueState(&sb, issue, issueStateNotFixed, color.New(color.FgRed, color.Bold))
	}
	fmt.Fprintln(&sb)

	issue = &tailcallIssueHierarchy
	if !haveBpf2bpf {
		printIssueState(&sb, issue, issueStateNotExists, color.New(color.FgGreen))
	} else if info.fixedTailcallHierarchy {
		printIssueState(&sb, issue, issueStateFixed, color.New(color.FgGreen, color.Bold))
	} else {
		printIssueState(&sb, issue, issueStateNotFixed, color.New(color.FgRed, color.Bold))
	}
	fmt.Fprintln(&sb)

	issue = &tailcallIssuePanicCausedByUpdatingAttachedFreplaceProgToProgArray
	if !haveFreplace || invalidTailcallee.issuePanicCausedByFreplaceNotExists {
		printIssueState(&sb, issue, issueStateNotExists, color.New(color.FgGreen))
	} else {
		printIssueState(&sb, issue, issueStateCannotDetect, color.New(color.FgYellow))
	}
	fmt.Fprintln(&sb)

	issue = &tailcallIssueInfiniteLoopCausedByFreplace
	if !haveFreplace || invalidTailcallee.issuePanicCausedByFreplaceNotExists {
		printIssueState(&sb, issue, issueStateNotExists, color.New(color.FgGreen))
	} else if invalidTailcallee.fixedInfiniteLoopCausedByFreplace {
		printIssueState(&sb, issue, issueStateFixed, color.New(color.FgGreen, color.Bold))
	} else {
		printIssueState(&sb, issue, issueStateNotFixed, color.New(color.FgRed, color.Bold))
	}

	fmt.Println(sb.String())
}
