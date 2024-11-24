# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

GOBUILD := go build -v -trimpath
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -lcapstone -static'

GOGEN := go generate

BPF_OBJ := invalid_bpfel.o invalid_bpfeb.o
BPF_SRC := bpf/invalid-offset.c

.DEFAULT_GOAL := build

$(BPF_OBJ): $(BPF_SRC)
	$(GOGEN)

.PHONY: build
build: $(BPF_OBJ)
	$(GOBUILD_CGO_LDFLAGS) $(GOBUILD)

.PHONY: clean
clean:
	rm -f $(BPF_OBJ)
	rm -f tailcall-issues
