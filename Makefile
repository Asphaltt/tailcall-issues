# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

GOBUILD := go build -v -trimpath
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -lcapstone -static'

GOGEN := go generate

BPF_OBJ_INVALID_OFFSET := invalid_bpfel.o invalid_bpfeb.o
BPF_SRC_INVALID_OFFSET := bpf/invalid-offset.c

BPF_OBJ_BPF2BPF := subprog_bpfeb.o subprog_bpfel.o
BPF_SRC_BPF2BPF := bpf/bpf2bpf.c

BPF_OBJ_LOOP := loop_bpfeb.o loop_bpfel.o
BPF_SRC_LOOP := bpf/infinite-loop-caused-by-trampoline.c

BPF_OBJ_INVALID_TAILCALLEE := invalidtailcallee_bpfeb.o invalidtailcallee_bpfel.o
BPF_SRC_INVALID_TAILCALLEE := bpf/invalid-tailcallee.c

.DEFAULT_GOAL := build

$(BPF_OBJ_INVALID_OFFSET): $(BPF_SRC_INVALID_OFFSET)
	$(GOGEN) ./invalid_offset.go

$(BPF_OBJ_BPF2BPF): $(BPF_SRC_BPF2BPF)
	$(GOGEN) ./bpf2bpf.go

$(BPF_OBJ_LOOP): $(BPF_SRC_LOOP)
	$(GOGEN) ./detection.go

$(BPF_OBJ_INVALID_TAILCALLEE): $(BPF_SRC_INVALID_TAILCALLEE)
	$(GOGEN) ./invalid_tailcallee.go

.PHONY: build
build: $(BPF_OBJ_INVALID_OFFSET) $(BPF_OBJ_BPF2BPF) $(BPF_OBJ_LOOP) $(BPF_OBJ_INVALID_TAILCALLEE)
	$(GOBUILD_CGO_LDFLAGS) $(GOBUILD)

.PHONY: clean
clean:
	rm -f $(BPF_OBJ_INVALID_OFFSET) $(BPF_OBJ_BPF2BPF) $(BPF_OBJ_LOOP) $(BPF_OBJ_INVALID_TAILCALLEE)
	rm -f tailcall-issues
