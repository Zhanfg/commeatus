# eBPF

Commeatus treats eBPF as a platform capability, not as the proxy protocol runtime.

## Current prototype

`flow.bpf.c` is a **compile-only attach-point proof** for:

- `cgroup/connect4`
- `cgroup/connect6`

Both programs currently return allow (`1`) and deliberately do not redirect,
mark, rewrite or block traffic. No loader is shipped yet. This means the current
prototype is safe to compile in CI and does **not** claim live Android eBPF
interception.

The purpose of this stage is to freeze the boundary before implementation:

```text
socket connect
    ↓
cgroup connect4/connect6
    ↓
classify / consult future policy map
    ├─ DIRECT → native stack
    └─ PROXY  → future interception backend
```

## Next eBPF stages

1. BTF/CO-RE build input and stable map ABI.
2. Read-only UID/network policy maps.
3. Rust loader inside `commeatus-platform`.
4. Capability-gated Android/Linux attach/detach lifecycle.
5. Atomic map generation swaps and crash cleanup.
6. Direct fast path and proxy redirection only after fallback paths are proven.

TPROXY and TUN remain separate backends. An eBPF load/attach failure must degrade
to another supported backend rather than become a global network outage.
