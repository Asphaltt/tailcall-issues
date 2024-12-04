# tailcall-issues: A tool to detect tailcall issues

```bash
tailcall issues:

ISSUE:  invalid tailcallee
COMMIT: 1c123c567fb1 ("bpf: Resolve fext program type when checking map compatibility")
URL:    https://github.com/torvalds/linux/commit/1c123c567fb138ebd187480b7fc0610fcb0851f5
PATCH:  https://lore.kernel.org/all/20221214230254.790066-1-toke@redhat.com/
RANGE:  v5.6 -> v6.2

ISSUE:  invalid loading offset of tail_call_cnt for bpf2bpf
COMMIT: ff672c67ee76 ("bpf, x86: Fix tail call count offset calculation on bpf2bpf call")
URL:    https://github.com/torvalds/linux/commit/ff672c67ee7635ca1e28fb13729e8ef0d1f08ce5
PATCH:  https://lore.kernel.org/bpf/20220616162037.535469-1-jakub@cloudflare.com/
RANGE:  v5.10 -> v5.19

ISSUE:  tailcall infinite loop caused by trampoline
COMMIT: 2b5dcb31a19a ("bpf, x64: Fix tailcall infinite loop")
URL:    https://github.com/torvalds/linux/commit/2b5dcb31a19a2e0acd869b12c9db9b2d696ef544
PATCH:  https://lore.kernel.org/bpf/20230912150442.2009-1-hffilwlqm@gmail.com/
RANGE:  v5.10 -> v6.7

ISSUE:  tailcall hierarchy
COMMIT: 116e04ba1459 ("bpf, x64: Fix tailcall hierarchy")
URL:    https://github.com/torvalds/linux/commit/116e04ba1459fc08f80cf27b8c9f9f188be0fcb2
PATCH:  https://lore.kernel.org/bpf/20240714123902.32305-1-hffilwlqm@gmail.com/
RANGE:  v5.10 -> v6.12

ISSUE:  panic caused by updating attached freplace prog to prog array
COMMIT: fdad456cbcca ("bpf: Fix updating attached freplace prog in prog_array map")
URL:    https://github.com/torvalds/linux/commit/fdad456cbcca739bae1849549c7a999857c56f88
PATCH:  https://lore.kernel.org/bpf/20240728114612.48486-1-leon.hwang@linux.dev/
RANGE:  v6.2 -> v6.11

ISSUE:  tailcall infinite loop caused by freplace
COMMIT: d6083f040d5d ("bpf: Prevent tailcall infinite loop caused by freplace")
URL:    https://github.com/torvalds/linux/commit/d6083f040d5d8f8d748462c77e90547097df936e
PATCH:  https://lore.kernel.org/bpf/20241015150207.70264-1-leon.hwang@linux.dev/
RANGE:  v6.2 -> v6.13
```

Detection on Ubuntu 24.04 v6.8 kernel:

```bash
# uname -r
6.8.0-35-generic

# ./tailcall-issues
detection results:

issue:  invalid tailcallee
state:  fixed

issue:  invalid loading offset of tail_call_cnt for bpf2bpf
state:  fixed

issue:  tailcall infinite loop caused by trampoline
state:  fixed

issue:  tailcall hierarchy
state:  not fixed

issue:  panic caused by updating attached freplace prog to prog array
state:  cannot detect

issue:  tailcall infinite loop caused by freplace
state:  not fixed
```

Detection on Ubuntu 22.04 v5.15 kernel:

```bash
# uname -r
5.15.0-051500-generic

# ./tailcall-issues
detection results:

issue:  invalid tailcallee
state:  not fixed

issue:  invalid loading offset of tail_call_cnt for bpf2bpf
state:  not fixed

issue:  tailcall infinite loop caused by trampoline
state:  not fixed

issue:  tailcall hierarchy
state:  not fixed

issue:  panic caused by updating attached freplace prog to prog array
state:  not exists

issue:  tailcall infinite loop caused by freplace
state:  not exists
```

## Build

`capstone-engine` library is required to build `tailcall-issues` tool. Install it by:

```bash
# apt install libcapstone-dev
```

LLVM and Go are also required to build the tool.

Then, build the tool by:

```bash
# make
```
