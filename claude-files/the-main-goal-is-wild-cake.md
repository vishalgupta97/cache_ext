# Plan: Reimplement cache_ext BPF API in BPF (via forward-port to Linux v7.0)

## Context

`cache_ext` (this repo, kernel at `linux/`, based on **Linux v6.6.8**) lets BPF programs
customize the page-cache eviction policy. Today the data-structure operations a policy needs —
linked lists of folios, iteration, sampling — are **kernel kfuncs**
(`bpf_cache_ext_list_add/_del/_move/_iterate/_iterate_extended/_sample`,
`bpf_cache_ext_ds_registry_new_list` in `linux/mm/cache_ext_ds.c`). They live in the kernel,
not in BPF, because a BPF policy that builds its own data structure (with `bpf_spin_lock` +
`bpf_list_head`/`bpf_rbtree`) could loop forever or wedge while holding a lock **on the reclaim
path**, hanging the machine. v6.6.8 has no way to forcibly terminate such a program and roll
back its partial writes.

A separate kernel tree at **`/home/vishal/ebpf/linux` (Linux v7.0)** already implements exactly
the missing safety net: **BPF spinlock timeout/termination** (a watchdog that aborts a program
stuck under a BPF lock via `bpf_throw`) and **undo logging** (the verifier instruments writes in
lock critical sections so they roll back on abort), plus the **BPF qspinlock** they build on.

**Decision (made with the user):** rather than backport that fragile verifier/JIT feature stack
into v6.6.8, **forward-port cache_ext onto the v7.0 tree**, which already has termination, undo,
qspinlock, `bpf_throw`, and arena — all confirmed present and tested. Then expose folios through
the (newer) verifier and reimplement the cache_ext kfuncs as pure BPF, with unit + system tests
at every step.

### Why this direction (verified facts)
- v7.0 tree has **no cache_ext** today → clean forward-port, not a merge.
- cache_ext is **~1,900 lines**: ~1,040 in **self-contained new files** (`mm/cache_ext_ds.c`
  748, `mm/cache_ext.c` 187, `include/linux/cache_ext.h` 105) that move over nearly as-is; only
  ~850 lines are hooks in `mm/{filemap,vmscan,swap,memcontrol}.c`, `kernel/bpf/bpf_struct_ops.c`
  (202), `kernel/bpf/verifier.c` (86), `include/linux/{mm_types.h,memcontrol.h,bpf-cgroup-defs.h}`.
- **struct_ops registration API changed:** v6.6.8 uses the old `bpf_struct_ops_types.h` array;
  **v7.0 uses BTF_ID-based registration** (`register_bpf_struct_ops`, no central types.h). The
  cache_ext registration is rewritten against this — fewer touch points, not more.
- Backporting the other way would mean porting BPF exceptions + undo verifier/JIT instrumentation
  into v6.6.8's **older** verifier/JIT — the highest-risk kind of kernel work. Forward-porting
  avoids it entirely and lands the project on the kernel where the end-goal infra is first-class.

### Cost accepted
The SOSP artifact (install scripts, benchmark harness, `uname -r | grep cache-ext` guards,
kernel configs, MGLRU toggles) assumes `6.6.8-cache-ext+`. These need re-pointing at the v7.0
kernel and re-validation — surface-level, and needed on any new kernel anyway.

---

## Milestone 0 — Set up the v7.0 working tree + test harness

- In `/home/vishal/ebpf/linux` (v7.0 + termination/undo), create a working branch for the
  forward-port. This becomes the new kernel the artifact builds. Decide submodule strategy:
  re-point the cache_ext repo's `linux/` at this branch (or vendor it) — keep the v6.6.8 tree
  available for side-by-side reference.
- **User action — install the v7.0 base kernel:** the user runs the (updated) `install_kernel.sh`
  for the v7.0 tree and **reboots into it** themselves (Claude cannot reboot; suggest running it
  with `! <command>` / under `screen` since the build is long). Subsequent steps assume the host
  is booted into the v7.0 kernel.
- The v7.0 tree already builds `tools/testing/selftests/bpf` `test_progs`; use it as the unit
  harness. Reuse its `bpftest-config` and confirm the **termination/undo selftests already pass**
  on this tree (`spin_lock_timeout`, `spin_lock_loop_timeout`, `minimal_bpf_undo_log`,
  `bpf_undo_log`) — this is the baseline we build on. **Skip `spin_lock_mt_timeout`** (flaky/slow
  multi-threaded test) throughout.
- **Test gate:** v7.0 kernel builds + boots (user-installed); the above term/undo selftests green.

---

## Milestone 1 — Forward-port cache_ext onto v7.0 (detailed)

Goal: the **existing** kfunc-based cache_ext compiles, boots, and runs its current policies
unchanged on v7.0. No new BPF behavior yet — this is a faithful port. Each sub-step is testable.

Reference originals from the v6.6.8 tree (`/home/vishal/ebpf/cache_ext/linux`); place equivalents
in the v7.0 tree.

### 1.1 Port the self-contained core (low risk — near drop-in)
- `mm/cache_ext.c` (struct_ops glue, verifier ops, reg/unreg), `mm/cache_ext_ds.c` (the list/
  registry/iterate/sample kfuncs), `include/linux/cache_ext.h` (DS structs), the cache_ext
  fields in `include/linux/mm_types.h` (`cache_ext_ops` vtable, `cache_ext_eviction_ctx`,
  `cache_ext_admission_ctx`), and `include/linux/bpf-cgroup-defs.h` (`cache_ext_enabled/_ops/
  _sem`). Adapt only for header/API renames (folio helpers, `mem_cgroup` layout).
- Add to `mm/Makefile`.
- **Test:** kernel compiles with the new files (no hook wiring yet).

### 1.2 Rewrite struct_ops registration for v7.0 (medium)
- Replace the old `bpf_struct_ops_types.h` entry + central switch with v7.0's
  `register_bpf_struct_ops(&bpf_cache_ext_ops, cache_ext_ops)` (BTF_ID-based). Keep the
  `struct bpf_struct_ops bpf_cache_ext_ops` descriptor and its `.verifier_ops` (is_valid_access,
  btf_struct_access, get_func_proto) — adapt signatures to v7.0 `btf_ctx_access`/verifier hooks.
- Re-register the cache_ext kfunc set (`cache_ext_list_ops` BTF_SET8) against v7.0 kfunc
  registration.
- **Test:** `bpftool struct_ops` lists `cache_ext_ops`; a trivial policy skeleton loads + the
  vtable verifies.

### 1.3 Re-place the mm hooks (the real work — placement, not logic)
Each hook is a small `get_cache_ext_ops(memcg)` + vtable call; the risk is finding the right
v7.0 site since these files churned 6.6→7.0.
- `mm/swap.c` — `folio_mark_accessed` → `folio_accessed` (lowest risk; site stable).
- `mm/filemap.c` — `folio_added` (in `filemap_add_folio`), `folio_evicted` (in
  `__filemap_remove_folio` + the batch remove loop), `admit_folio` + DIO fallback in the read
  path; plus `valid_folios_add/del`.
- `mm/vmscan.c` — `cache_ext_isolate_and_reclaim` + `__cache_ext_isolate_and_reclaim` wired into
  `shrink_lruvec` (re-place against v7.0 reclaim; folio isolation helpers may have changed).
- `mm/memcontrol.c` — **highest risk** (memcg changed most): `get_cache_ext_ops`,
  `add_cache_ext_structures`, `init_valid_folios_set` + `cache_ext_ds_registry_init` per node,
  the `cache_ext_valid` flag and cgroup-name match. Re-place against v7.0 memcg/nodeinfo layout.
- `include/linux/memcontrol.h` — `valid_folios` set + per-memcg fields.
- `kernel/bpf/verifier.c` — the cache_ext-specific access checks (86 lines) against v7.0 verifier.
- **Test (per file where practical):** rebuild; boot; for each hook, a smoke policy that logs via
  `bpf_printk` confirms the callback fires (e.g. `folio_added` on file reads under the cgroup).

### 1.4 Build + install + boot the v7.0-cache_ext kernel
- Merge required configs (cache_ext on; `CONFIG_BPF_TIMEOUT`/`CONFIG_BPF_UNDO_LOG`/qspinlock
  already in the v7.0 config). Update the `uname -r | grep cache-ext` guards for the new version
  string.
- **User action:** the user runs the updated `install_kernel.sh` and **reboots into the
  v7.0-cache_ext kernel** themselves (Claude cannot reboot; long build — use `screen`). Claude
  resumes verification once the host is booted into it.
- **Test:** boots; `dmesg` clean; selftests from M0 still green (excluding `spin_lock_mt_timeout`).

### 1.5 Validate existing policies end-to-end on v7.0
- `./build_policies.sh` (still using the kfuncs); load **FIFO**, then **sampling**, then
  **s3fifo** against a scratch `cache_ext_test` cgroup via the existing loaders
  (`policies/cache_ext_*.c`); confirm attach, eviction activity, clean detach.
- **Test gate (M1 exit):** all current policies behave on v7.0 as they did on v6.6.8 — the
  forward-port is functionally complete and the kfunc API is unchanged.

---

## Milestone 2 — Re-validate artifact tooling on v7.0

- Update `install_*.sh`, `setup_isolation.sh`, `build_policies.sh`, the `eval/*/run.sh` kernel
  guards, MGLRU toggles (`utils/{enable,disable}-mglru.sh`), and `bench/bench_lib.py` cgroup
  setup for any v7.0 differences (cgroup layout, sysfs paths, MGLRU knobs).
- **Test:** a **reduced** `eval/filesearch/run.sh` (`ITERATIONS=1`, one policy) completes and
  writes sane `results/` JSON; numbers are plausible vs the v6.6.8 baseline (sanity, not parity).

---

## Milestone 3 — Expose folios through the verifier (sketch)

On v7.0's newer verifier this is easier than on 6.6.8. Replace the hand-rolled bit-poking
(`folio_test_*`, `folio_flags`, `READ_ONCE` in `policies/cache_ext_lib.bpf.h`) with
verifier-checked folio access: register `struct folio` as a BTF-trusted type, mark hook/kfunc
folio args `KF_TRUSTED_ARGS`, expose needed fields (`flags`, `index`, `mapping`) via
`BTF_TYPE_SAFE_*`/`bpf_rdonly_cast`.
- **Tests:** BPF prog reads `folio->index`/flags through verifier-checked access; verifier
  rejects untrusted/out-of-bounds folio access; existing policies still load.

---

## Milestone 4 — Reimplement cache_ext kfuncs as pure BPF (sketch)

Now safe thanks to native termination + undo, move the DS ops from kernel kfuncs into a BPF
library (e.g. `policies/cache_ext_ds.bpf.h`) built on `bpf_list_head`/`bpf_rbtree` +
`bpf_spin_lock` with folio `kptr` nodes.
- Reimplement one at a time: `list_add`/`add_tail`/`del`/`move` → `iterate`/`iterate_extended`
  (callback returns `CACHE_EXT_EVICT_NODE`/`CONTINUE`/`STOP`) → `sample` (score-fn min-K) →
  `ds_registry_new_list`. Keep kfunc versions side-by-side until equivalence holds.
- Migrate policies easiest-first: **FIFO** → **sampling** → **s3fifo** (multi-list moves).
- **Tests:** per-op unit tests (add N + iterate order, del/move, sample selection); equivalence
  tests comparing BPF-DS policy vs kfunc policy on the same access trace.

---

## Milestone 5 — Full system tests + termination proof (sketch)

- Run `bench/bench_leveldb.py` + `bench_filesearch.py` (reduced configs) with the BPF-DS
  policies; compare hit-rate/throughput against the kfunc baseline for **correctness**.
- Add a **fault-injection policy** (infinite loop under lock; deliberate list corruption) and
  confirm the live eviction path triggers termination + undo rollback instead of hanging — the
  end-to-end proof that the foundation works where it matters.

---

## Critical files

**New kernel base (v7.0):** `/home/vishal/ebpf/linux` — already has `bpf_throw`,
`kernel/bpf/arena.c`, `kernel/bpf/bpf_qspinlock.c`, term/undo selftests, `bpftest-config`.

**Forward-port targets (v7.0 tree):** new `mm/cache_ext.c`, `mm/cache_ext_ds.c`,
`include/linux/cache_ext.h`; hooks in `mm/{filemap,vmscan,swap,memcontrol}.c`,
`kernel/bpf/{bpf_struct_ops.c,verifier.c}`, `include/linux/{mm_types.h,memcontrol.h,
bpf-cgroup-defs.h}`, `mm/Makefile`.

**Originals to port from (v6.6.8):** same paths under `/home/vishal/ebpf/cache_ext/linux`
(see the line counts in Context).

**Artifact / userspace:** `install_kernel.sh`, `install_*.sh`, `build_policies.sh`,
`setup_isolation.sh`, `utils/{enable,disable}-mglru.sh`, `eval/*/run.sh`, `bench/bench_lib.py`,
`policies/cache_ext_lib.bpf.h`, `policies/cache_ext_{fifo,sampling,s3fifo}.{bpf.c,c}`,
`policies/Makefile`.

## Verification

- **Kernel build/boot (user action):** the **user** runs the updated `./install_kernel.sh` and
  **reboots** into the v7.0-cache_ext kernel (long build; use `screen`) — Claude cannot reboot.
  Update the `uname -r | grep cache-ext` guards for the new version string.
- **Unit (per step):** `test_progs -t <name>` on the v7.0 selftests harness; term/undo tests with
  the `bpf_spin_lock_timeout` sysctl; **skip `spin_lock_mt_timeout`**; cache_ext DS unit tests
  added in M4.
- **Policy smoke:** `./build_policies.sh` + load FIFO/sampling/s3fifo via `policies/cache_ext_*.c`
  against a scratch cgroup; confirm attach/evict/detach.
- **System:** reduced-config `eval/*/run.sh` (`ITERATIONS=1`) + the M5 fault-injection policy in
  the live eviction path.
