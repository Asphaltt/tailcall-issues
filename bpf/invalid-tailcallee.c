// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

/* make it look to compiler like value is read and written */
#define __sink(expr) asm volatile("" : "+g"(expr))

char __license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

SEC("freplace")
int freplace_tailcallee_invalid(struct __sk_buff *skb)
{
    return 0;
}

SEC("freplace")
int freplace_tailcallee(struct xdp_md *xdp)
{
    return 0;
}

SEC("freplace")
int freplace_entry(struct xdp_md *xdp)
{
    bpf_tail_call_static(xdp, &jmp_table, 0);
    return 0;
}

__noinline
int xdp_subprog(struct xdp_md *xdp)
{
    return xdp->data ? 1 : 0;
}

SEC("xdp")
int entry(struct xdp_md *xdp)
{
    return xdp_subprog(xdp);
}

__noinline
int tc_subprog(struct __sk_buff *skb)
{
    return skb->len;
}

SEC("tc")
int tc_entry(struct __sk_buff *skb)
{
    return tc_subprog(skb);
}
