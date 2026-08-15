// SPDX-License-Identifier: Apache-2.0
// Commeatus eBPF prototype: compile/attach-point proof only.
//
// This program deliberately performs no redirect and changes no packet/socket
// state. It establishes the cgroup connect4/connect6 ABI and CI toolchain before
// a userspace loader or live policy maps are introduced.

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

SEC("cgroup/connect4")
int commeatus_connect4(struct bpf_sock_addr *ctx)
{
    (void)ctx;
    return 1;
}

SEC("cgroup/connect6")
int commeatus_connect6(struct bpf_sock_addr *ctx)
{
    (void)ctx;
    return 1;
}

char LICENSE[] SEC("license") = "Apache-2.0";
