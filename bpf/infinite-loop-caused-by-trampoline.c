// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

SEC("fentry")
int BPF_PROG(fentry_fn)
{
    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
