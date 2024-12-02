// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

const (
	issueStateNotExists = "not exists"
	issueStateFixed     = "fixed"
	issueStateNotFixed  = "not fixed"

	issueStateCannotDetect = "cannot detect"
)

type tailcallIssue struct {
	name string

	commit      string
	commitTitle string
	commitURL   string
	patchURL    string

	fixedKernelVersion string
	sinceKernelVersion string

	requiredBpf2bpf  bool
	requiredFreplace bool
}

var tailcallIssueInvalidOffset = tailcallIssue{
	name:        "invalid loading offset of tail_call_cnt for bpf2bpf",
	commit:      "ff672c67ee76",
	commitTitle: "bpf, x86: Fix tail call count offset calculation on bpf2bpf call",
	commitURL:   "https://github.com/torvalds/linux/commit/ff672c67ee7635ca1e28fb13729e8ef0d1f08ce5",
	patchURL:    "https://lore.kernel.org/bpf/20220616162037.535469-1-jakub@cloudflare.com/",

	fixedKernelVersion: "v5.19",
	sinceKernelVersion: "v5.10",

	requiredBpf2bpf: true,
}

var tailcallIssueInfiniteLoopCausedByTrampoline = tailcallIssue{
	name:        "tailcall infinite loop caused by trampoline",
	commit:      "2b5dcb31a19a",
	commitTitle: "bpf, x64: Fix tailcall infinite loop",
	commitURL:   "https://github.com/torvalds/linux/commit/2b5dcb31a19a2e0acd869b12c9db9b2d696ef544",
	patchURL:    "https://lore.kernel.org/bpf/20230912150442.2009-1-hffilwlqm@gmail.com/",

	fixedKernelVersion: "v6.7",
	sinceKernelVersion: "v5.10",

	requiredBpf2bpf: true,
}

var tailcallIssueHierarchy = tailcallIssue{
	name:        "tailcall hierarchy",
	commit:      "116e04ba1459",
	commitTitle: "bpf, x64: Fix tailcall hierarchy",
	commitURL:   "https://github.com/torvalds/linux/commit/116e04ba1459fc08f80cf27b8c9f9f188be0fcb2",
	patchURL:    "https://lore.kernel.org/bpf/20240714123902.32305-1-hffilwlqm@gmail.com/",

	fixedKernelVersion: "v6.12",
	sinceKernelVersion: "v5.10",

	requiredBpf2bpf: true,
}

var tailcallIssueInfiniteLoopCausedByFreplace = tailcallIssue{
	name:        "tailcall infinite loop caused by freplace",
	commit:      "d6083f040d5d",
	commitTitle: "bpf: Prevent tailcall infinite loop caused by freplace",
	commitURL:   "https://github.com/torvalds/linux/commit/d6083f040d5d8f8d748462c77e90547097df936e",
	patchURL:    "https://lore.kernel.org/bpf/20241015150207.70264-1-leon.hwang@linux.dev/",

	fixedKernelVersion: "v6.13",
	sinceKernelVersion: "v6.2",

	requiredBpf2bpf:  true,
	requiredFreplace: true,
}

var tailcallIssuePanicCausedByUpdatingAttachedFreplaceProgToProgArray = tailcallIssue{
	name:        "panic caused by updating attached freplace prog to prog array",
	commit:      "fdad456cbcca",
	commitTitle: "bpf: Fix updating attached freplace prog in prog_array map",
	commitURL:   "https://github.com/torvalds/linux/commit/fdad456cbcca739bae1849549c7a999857c56f88",
	patchURL:    "https://lore.kernel.org/bpf/20240728114612.48486-1-leon.hwang@linux.dev/",

	fixedKernelVersion: "v6.11",
	sinceKernelVersion: "v6.2",

	requiredFreplace: true,
}

var tailcallIssueInvalidTailcallee = tailcallIssue{
	name:        "invalid tailcallee",
	commit:      "1c123c567fb1",
	commitTitle: "bpf: Resolve fext program type when checking map compatibility",
	commitURL:   "https://github.com/torvalds/linux/commit/1c123c567fb138ebd187480b7fc0610fcb0851f5",
	patchURL:    "https://lore.kernel.org/all/20221214230254.790066-1-toke@redhat.com/",

	fixedKernelVersion: "v6.2",
	sinceKernelVersion: "v5.6",

	requiredFreplace: true,
}

func printIssueDetails(w io.Writer, issue *tailcallIssue) {
	fmt.Fprintf(w, "ISSUE:\t%s\n", color.RedString(issue.name))
	fmt.Fprintf(w, "COMMIT:\t%s (\"%s\")\n", issue.commit, issue.commitTitle)
	fmt.Fprintf(w, "URL:\t%s\n", issue.commitURL)
	fmt.Fprintf(w, "PATCH:\t%s\n", issue.patchURL)
	fmt.Fprintf(w, "RANGE:\t%s -> %s\n", issue.sinceKernelVersion, issue.fixedKernelVersion)
}

func printIssueState(w io.Writer, issue *tailcallIssue, state string, cl *color.Color) {
	fmt.Fprintf(w, "issue:\t%s\n", color.RedString(issue.name))
	fmt.Fprintf(w, "state:\t%s\n", cl.Sprint(state))
}
