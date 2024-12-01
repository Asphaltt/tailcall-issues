// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"

static __noinline void
my_subprog(void)
{
    bpf_printk("my_subprog\n");
}

SEC("kprobe/tcp_connect")
int entry(struct pt_regs *ctx)
{
    my_subprog();
    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
