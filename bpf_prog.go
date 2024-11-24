// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/knightsc/gapstone"
)

type bpfProgInfo struct {
	id    ebpf.ProgramID
	name  string
	jited bool

	tailCallReachable      bool
	fixedTailcallHierarchy bool

	issueInvalidOffset bool

	hasStack   bool
	stackDepth uint32
}

func newBpfProgInfo(prog *ebpf.Program) (*bpfProgInfo, error) {
	pinfo, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get program info: %w", err)
	}

	var info bpfProgInfo
	info.id, _ = pinfo.ID()
	info.name = pinfo.Name

	jitedKsyms, _ := pinfo.KsymAddrs()
	jitedInsns, _ := pinfo.JitedInsns()
	if len(jitedInsns) == 0 {
		return &info, nil
	}

	engine, err := gapstone.New(int(gapstone.CS_ARCH_X86), int(gapstone.CS_MODE_64))
	if err != nil {
		return nil, fmt.Errorf("failed to create disassembler: %w", err)
	}
	defer engine.Close()

	info.jited = true

	var insns []gapstone.Instruction

	b := jitedInsns
	kaddr, pc := jitedKsyms[0], uint64(0)
	for i := 0; len(b) != 0; i++ {
		insts, err := engine.Disasm(b, uint64(kaddr)+pc, 1)
		if err != nil {
			return nil, fmt.Errorf("failed to disassemble instruction: %w", err)
		}

		insn := insts[0]
		insns = append(insns, insn)

		insnSize := insn.Size
		pc += uint64(insnSize)
		b = b[insnSize:]
	}

	idxPushRbp := -1
	for i := range insns {
		insn := insns[i]
		if len(insn.Bytes) == 1 && insn.Bytes[0] == 0x55 {
			idxPushRbp = i
			break
		}
	}
	if idxPushRbp == -1 {
		return nil, fmt.Errorf("failed to find push rbp instruction")
	}

	insn := insns[idxPushRbp-1]
	info.tailCallReachable = len(insn.Bytes) == 2 && insn.Bytes[0] == 0x31 && insn.Bytes[1] == 0xc0
	if !info.tailCallReachable {
		return &info, nil
	}

	idxPushRax := -1
	for i := idxPushRbp + 1; i < len(insns); i++ {
		insn := insns[i]
		if len(insn.Bytes) == 1 && insn.Bytes[0] == 0x50 {
			idxPushRax = i
			break
		}
	}
	if idxPushRax == -1 {
		return nil, fmt.Errorf("failed to find push rax instruction")
	}

	insn = insns[idxPushRax-1]
	info.fixedTailcallHierarchy = len(insn.Bytes) == 2 && insn.Bytes[0] == 0x77 && insn.Bytes[1] == 0x06 // ja 6
	if info.fixedTailcallHierarchy {
		return &info, nil
	}

	idxSubRsp := idxPushRax - 1

	insn = insns[idxSubRsp]
	if len(insn.Bytes) == 7 && bytes.Equal(insn.Bytes[:3], []byte{0x48, 0x81, 0xec}) {
		info.stackDepth = binary.LittleEndian.Uint32(insn.Bytes[3:])
		info.hasStack = true
	}

	if info.stackDepth == 0 {
		return &info, nil
	}

	idxCall := -1
	for i := idxPushRax + 1; i < len(insns); i++ {
		insn := insns[i]
		if len(insn.Bytes) == 5 && insn.Bytes[0] == 0xe8 /* call */ {
			idxCall = i
			break
		}
	}
	if idxCall == -1 {
		return nil, fmt.Errorf("failed to find call instruction")
	}

	insn = insns[idxCall-1] /* load tcc from stack to rax */
	if len(insn.Bytes) != 7 || !bytes.Equal(insn.Bytes[:3], []byte{0x48, 0x8b, 0x85}) {
		return nil, fmt.Errorf("failed to find insn fro loading tcc from stack to rax")
	}

	offset := -int32(binary.LittleEndian.Uint32(insn.Bytes[3:]))
	info.issueInvalidOffset = (offset & 0x7) != 0

	return &info, nil
}
