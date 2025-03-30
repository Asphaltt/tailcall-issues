//go:build ignore
// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

static __noinline int
subprog(void *ctx, struct sock *sk)
{
    bpf_printk("subprog called with ctx=%llx sk=%llx\n",
               (unsigned long long)ctx, (unsigned long long)sk);
    bpf_tail_call_static(ctx, &jmp_table, 0);

    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(k_tcp_connect, struct sock *sk)
{
    return subprog(ctx, sk);
}

SEC("fexit/subprog")
int BPF_PROG(fexit_subprog, void *pctx, struct sock *sk)
{
    bpf_printk("fexit_subprog called with pctx=%llx sk=%llx\n",
               (unsigned long long) pctx, (unsigned long long)sk);
    return 0;
}
