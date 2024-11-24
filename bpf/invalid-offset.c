// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

/* make it look to compiler like value is read and written */
#define __sink(expr) asm volatile("" : "+g"(expr))

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} array_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

static __noinline void
my_tailcall_inspect(void *ctx, void *map, __u32 slot)
{
    bpf_printk("my_tailcall_inspect, ctx: %016llx, map: %016llx, slot: %u\n", ctx, map, slot);
}

static __noinline int
my_tailcall(void *ctx)
{
    void *map = (void *)(unsigned long)&jmp_table;
    volatile int retval = 0;
    __u32 slot = 0;

    __sink(retval);

    bpf_tail_call_static(ctx, map, slot);
    my_tailcall_inspect(ctx, map, slot);

    bpf_printk("tailcaller, after bpf_tail_call(). should not print this log\n");

    return retval;
}

SEC("kprobe/tcp_connect")
int entry(struct pt_regs *ctx)
{
    // __u64 key = 0; /* Consume 8 bytes of stack space. */
    __u32 key = 0; /* Consume 4 bytes of stack space. */
    __u32 *value;

    value = bpf_map_lookup_elem(&array_map, &key);
    bpf_printk("tailcaller, before bpf_tail_call(): %d\n", value ? *value: 0);

    return my_tailcall(ctx);
}

SEC("kprobe/tcp_connect")
int tailcallee(struct pt_regs *ctx)
{
    bpf_printk("tailcallee, should print this log\n");
    return 0;
}

char __license[] SEC("license") = "GPL";
