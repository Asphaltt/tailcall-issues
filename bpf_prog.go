// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/Asphaltt/tailcall-issues/internal/assert"
	"github.com/cilium/ebpf"
	"github.com/knightsc/gapstone"
)

const (
	kcorePath = "/proc/kcore"
)

type bpfProgInfo struct {
	id    ebpf.ProgramID
	name  string
	jited bool

	tailCallReachable bool

	fixedTailcallHierarchy                      bool
	fixedTailcallInfiniteLoopCausedByTrampoline bool
	failedDetectInfiniteLoopCausedByTrampoline  bool

	issueInvalidOffset bool

	hasStack   bool
	stackDepth uint32
}

func newBpfProgInfo(prog *ebpf.Program, checkTramp bool) (*bpfProgInfo, error) {
	pinfo, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get program info: %w", err)
	}

	var info bpfProgInfo
	info.id, _ = pinfo.ID()
	info.name = pinfo.Name

	jitedKsyms, _ := pinfo.JitedKsymAddrs()
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
	info.tailCallReachable = bytes.Equal(insn.Bytes, []byte{0x31, 0xc0}) /* xor eax, eax */ ||
		bytes.Equal(insn.Bytes, []byte{0x48, 0x31, 0xc0}) /* xor rax, rax */
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

	if !checkTramp {
		return &info, nil
	}

	opcodes := insns[0].Bytes
	if opcodes[0] != 0xe8 /* callq */ {
		return &info, fmt.Errorf("failed to find callq instruction")
	}

	kaddrTramp := jitedKsyms[0] + uintptr(binary.NativeEndian.Uint32(opcodes[1:])) + 5 /* callq */

	var data []byte

	for i := 0; i < 5; i++ {
		buf, ok := readKcore(uint64(kaddrTramp), 300)
		if ok {
			data = buf
			break
		}

		time.Sleep(1 * time.Second)
	}

	if len(data) == 0 {
		info.failedDetectInfiniteLoopCausedByTrampoline = true
		return &info, nil
	}

	insns, b, pc = insns[:0], data[:], uint64(kaddrTramp)
	for len(b) != 0 {
		insts, err := engine.Disasm(b, pc, 1)
		if err != nil && len(b) <= 10 {
			break
		}
		if err != nil {
			return &info, fmt.Errorf("failed to disassemble instruction: %w", err)
		}

		insn := insts[0]
		insns = append(insns, insn)

		insnSize := insn.Size
		if insnSize == 1 && insn.Bytes[0] == 0xc3 /* retq */ {
			break
		}

		pc += uint64(insnSize)
		b = b[insnSize:]
	}

	for i := range insns {
		insn := insns[i]
		if len(insn.Bytes) == 1 && insn.Bytes[0] == 0x50 /* pushq %rax */ {
			info.fixedTailcallInfiniteLoopCausedByTrampoline = true
			break
		}

		if len(insn.Bytes) == 1 && insn.Bytes[0] == 0xc3 /* retq */ {
			break
		}
	}

	return &info, nil
}

func readKcore(kaddr uint64, bytes uint) ([]byte, bool) {
	fd, err := os.Open(kcorePath)
	assert.NoErr(err, "Failed to open %s: %v", kcorePath)
	defer fd.Close()

	kcoreElf, err := elf.NewFile(fd)
	assert.NoErr(err, "Failed to read %s: %v", kcorePath)

	data := make([]byte, bytes)
	for _, prog := range kcoreElf.Progs {
		if prog.Vaddr <= kaddr && kaddr < prog.Vaddr+prog.Memsz {
			n, err := fd.ReadAt(data, int64(prog.Off+kaddr-prog.Vaddr))
			assert.NoErr(err, "Failed to read %s: %v", kcorePath)
			return data[:n], true
		}
	}

	return nil, false
}
