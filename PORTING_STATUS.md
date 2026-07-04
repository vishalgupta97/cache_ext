# cache_ext → Linux v7.0 forward-port: status, decisions, and remaining work

_Last updated: 2026-06-26_

## Goal

Reimplement the cache_ext **BPF data-structure API in BPF** instead of as kernel
kfuncs. The blocker on the original kernel (Linux v6.6.8) is that a BPF policy
which builds its own data structures (`bpf_spin_lock` + `bpf_list_head`) on the
**reclaim path** could loop forever or wedge while holding a lock, hanging the
machine, with no way to forcibly terminate it or roll back its partial writes.

**Decision (with user):** rather than backport the fragile termination/undo
verifier+JIT stack into v6.6.8, **forward-port cache_ext onto the v7.0 tree**
(`/home/vishal/ebpf/linux`), which already has BPF spinlock timeout/termination,
undo logging, BPF qspinlock, `bpf_throw`, and arena. Then expose folios through
the newer verifier and move the DS ops from kernel kfuncs into pure BPF, with
tests at each step.

## Repos and branches

| Tree | Path | Branch | Role |
|------|------|--------|------|
| v7.0 kernel | `/home/vishal/ebpf/linux` | `cache-ext-v7` | forward-port target (has term/undo/qspinlock) |
| v6.6.8 kernel | `/home/vishal/ebpf/cache_ext/linux` | — | **reference original** to port from |
| artifact / policies | `/home/vishal/ebpf/cache_ext` | `cache-ext-v7` | loaders, BPF policies, benchmarks |

Running kernel: `7.0.0-ebpftest-timeout-cache-ext+`.

---

## Milestones completed

### M0 — v7.0 working tree + harness
- v7.0 tree (`cache-ext-v7`) carries termination/undo + qspinlock and the
  `test_progs` selftest harness. Baseline term/undo selftests
  (`spin_lock_timeout`, `spin_lock_loop_timeout`, `minimal_bpf_undo_log`,
  `bpf_undo_log`) are the foundation we build on. **`spin_lock_mt_timeout` is
  skipped throughout** (flaky/slow multi-threaded).

### M1 — Forward-port kfunc-based cache_ext onto v7.0
Done across these kernel commits on `cache-ext-v7`:
- `3d2ca5e887` — forward-port of cache_ext core to v7.0: `mm/cache_ext.c`,
  `mm/cache_ext_ds.c`, `include/linux/cache_ext.h`, mm-types/memcontrol fields,
  and the mm hooks in `filemap.c` / `vmscan.c` / `swap.c` / `memcontrol.c`.
- struct_ops registration rewritten for v7.0's BTF_ID-based
  `register_bpf_struct_ops` (no central `bpf_struct_ops_types.h`).
- Policies adapted + building for v7.0 (`85b950b` in the artifact repo).

### M3 — Expose folios through the verifier
- `bc3ba51305` — `node->folio` exposed to BPF callbacks as a **trusted folio**.
- `2faf808` (artifact) — typed trusted-folio access + an M3 verifier test policy.

### M4 — Pure-BPF data structures (the core of the project)
Kernel enablers (v7.0 tree):
- `77b7b58cd2` — expose `mem_cgroup_per_node` to BPF as **writable memory**.
- `ff8f5f91d1` — `bpf_cache_ext_writable_cast` kfunc (re-type a kernel address to
  a writable BPF pointer).
- `0c0021e73c` — pass writable `mem_cgroup_per_node` to `folio_evicted`.
- `38f4dacaab` — pass writable parent node to `folio_accessed`.
- `b8333b2d22` — allow `bpf_loop` convergence under spin-lock + size the undo log
  for it.

Policy ports (artifact repo): a BPF DS library (`cache_ext_ds.bpf.h`) plus FIFO,
sampling, MRU, and s3fifo ported to pure-BPF list ops over the kernel-resident
nodes (`3e40cb3`, `34b48fa`, `9f62fe2`). The list is maintained in BPF:
`folio_added` links, `folio_accessed` moves, `folio_evicted` unlinks before the
kernel frees the node, `evict_folios` walks the list to pick victims. Only
`bpf_cache_ext_ds_registry_new_list` remains a kfunc (allocation).

### M4 lock-unification fix (the critical bug, fix implemented — **uncommitted**)
A real truncate/eviction workload GPF-crashed the box at `valid_folios_del`
(`0xdead000000000108` == LIST_POISON1+8). **Root cause:** the M4 pure-BPF list
ops took a `bpf_spin_lock` in a BPF map, while the kernel's `valid_folios_del`
took the registry `rwlock_t` — **two different locks, no mutual exclusion** — so
a BPF list walk raced the kernel's `list_del`+`kfree` → list-poison
use-after-free. (See `memory/m4-lock-mismatch-crash.md`.)

**Fix (option 2 — unify the lock; user-directed):** one lock shared between
kernel and BPF.
- `struct cache_ext_ds_registry.lock`: `rwlock_t` → **`spinlock_t`**. The kernel
  takes it with `spin_lock`/`spin_unlock`; BPF takes the **same word** with
  `bpf_spin_lock`/`bpf_spin_unlock` over a writable cast. This tree's
  `bpf_spin_lock` uses the standard qspinlock word format, so the two
  interoperate.
- New kfunc `bpf_cache_ext_registry_lock_addr(memcg)` returns `&registry->lock`
  as a scalar; BPF caches it at init (`cache_ext_ds_init_lock`) and re-casts it
  fresh at each lock/unlock (a writable-cast pointer can lose its type if spilled
  across calls).
- The BPF folio **lookup now runs under the lock** (lookup + cast + mutate all
  inside the critical section), so no node can be freed mid-op → no UAF.
- `valid_folios_del`: restored the `if (!list_empty(...)) list_del(...)` guard.
- `verifier.c`: `process_spin_lock` accepts a writable-cast (`MEM_WRITE`)
  `PTR_TO_BTF_ID` pointing at `struct bpf_spin_lock` (matched by type name) at
  off 0; added the type to `spin_lock_types` + a `check_reg_type` case.

**Why kernel waiters still make progress:** a BPF lock holder arms its own
watchdog on acquire; if it hangs under the lock, the spin-lock timeout handler
rolls back the undo log, force-releases the lock, and `bpf_throw()`s the program
— so a kernel `spin_lock` waiter proceeds. Termination, not a second lock,
guarantees kernel forward progress.

This fix **compiles** (all kernel objects + all 5 BPF policies) but is
**uncommitted** in both trees and **not yet rebuilt/rebooted/verified at
runtime**.

---

## Porting decisions (rationale, for future readers)

1. **Forward-port to v7.0, not backport to v6.6.8.** v7.0 already has the
   termination/undo/qspinlock infrastructure tested; v7.0 has no cache_ext (clean
   port, not a merge). Backporting the verifier/JIT undo machinery into an older
   verifier was judged the highest-risk path.

2. **One shared `spinlock_t`, not two locks or a BPF-map lock.** The principled
   M4 fix. Kernel uses `spin_lock`/`spin_unlock`; BPF uses
   `bpf_spin_lock`/`bpf_spin_unlock` on the same word (standard qspinlock format
   makes them interoperable). Rejected: keeping a separate BPF-map lock (the
   original crash) and restoring only the `list_empty` guard (partial fix only).

3. **Lock field is `spinlock_t`, not a raw `struct qspinlock`.** An earlier
   attempt used `bpf_qspinlock_lock((struct qspinlock *)…)` on the kernel side;
   corrected per user to standard `spin_lock`/`spin_unlock` on a `spinlock_t`.

4. **`rwlock_t` collapsed to a plain spinlock.** All former
   `read_lock`/`write_lock(&registry->lock)` sites became `spin_lock`. The three
   former reader sites are tagged `/* READER SITE */` and the read_lock/unlock
   helpers carry comments, so a future reader/writer BPF lock can revert them.

5. **`cache_ext_ds_registry_from_folio` uses `nodeinfo[0]`** (was
   `nodeinfo[pgdat->node_id]`) so the lock and the lists it guards always come
   from one registry per memcg — required for the single-lock scheme to be
   correct.

6. **Lookup-under-lock for node lifetime.** `valid_folios_del` frees the node
   *after* releasing the registry lock (still under `bucket_lock`), but the free
   is **gated** behind acquiring the registry lock for `list_del`. So a BPF op
   that does lookup+mutate atomically under the registry lock cannot race the
   free in any interleaving.

### Lock audit vs. v6.6.8 kfuncs (transferred as-is vs. changed)
- **Transferred as-is:** `cache_ext_sem`, the `bucket_locks[]`, the `nr_entries`
  atomic, and the `scoped_guard(preempt)` regions.
- **Changed:** `registry->lock` (rwlock → shared spinlock; `nodeinfo[0]`
  consistency; reader-collapse). The `list_empty` guard in `valid_folios_del` was
  **added** (it was commented out in both the v6.6.8 and v7.0 originals).
- **Known residual race (benign):** the BPF lookup walks the `valid_folios`
  hashtable **without** the `bucket_lock` (the v6.6.8 kfuncs took it). This is a
  `probe_read`-safe data race that cannot crash or touch freed memory — but see
  follow-ups.

---

## What is left

### Immediate — blocked on a USER action
1. **Rebuild + reboot the v7.0 kernel** with the uncommitted lock-unification
   changes. This is a user action (Claude cannot reboot):
   ```sh
   cd /home/vishal/ebpf/linux && make -j$(nproc) \
     && sudo make modules_install && sudo make install && sudo reboot
   ```

### After reboot — Claude can do
2. **Rebuild policies** (`make -C policies -j`) and **verify they LOAD** — the
   `verifier.c` change (accepting a writable-cast `bpf_spin_lock`) is unproven
   until a real load succeeds.
3. **Drive the crashing workload** (M2 functional test that the bug blocked):
   attach one pure-BPF policy to a scratch cgroup and run a real
   truncate/eviction workload while watching `dmesg`. Use an **ext4** test file
   (`/tmp` is tmpfs). This is the go/no-go for the fix.
4. **Commit** the kernel + verifier + BPF changes — **only when the user asks**.
   The lock-unification diff is currently uncommitted in both trees. (Do **not**
   commit the untracked `CLAUDE.md`.)

### Remaining milestones
5. **M2 — re-validate artifact tooling on v7.0:** kernel guards, MGLRU toggles,
   `bench/bench_lib.py` cgroup setup; a reduced `eval/filesearch/run.sh`
   (`ITERATIONS=1`, one policy) writing sane `results/` JSON.
6. **M5 — system tests + termination proof:** reduced `bench_leveldb.py` /
   `bench_filesearch.py` with BPF-DS policies vs. the kfunc baseline; a
   **fault-injection policy** (infinite loop under lock / deliberate list
   corruption) to prove the live eviction path triggers termination + undo
   rollback instead of hanging.

### Non-blocking follow-ups / cleanup
7. Close the residual **hashtable-walk race** (take/equiv of `bucket_lock` on the
   BPF lookup path), or document it as acceptable.
8. `cache_ext_m4test.bpf.c` still uses its own private lock (dev scratch) — either
   migrate it to the shared lock or drop it.
9. Remove the now-**dormant** DS-op kfuncs in `mm/cache_ext_ds.c`
   (`__cache_ext_list_add_impl` etc.) once pure-BPF policies are proven.

---

## Operational constraints (in force)
- Kernel install + reboot is a **user** action; Claude cannot reboot.
- **Never** `pkill -f cache_ext_` (matches the harness's own shell). Kill loaders
  by exact name: `pgrep -x` / `pkill -INT -x` (comm truncated to 15 chars).
- Do **not** commit until the user asks; commit trailer
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Do not commit the
  untracked `CLAUDE.md`.
- `/tmp` is tmpfs — use an ext4-backed test file for eviction tests.
- Do **not** attach a pure-BPF policy and drive real eviction until the rebuilt
  kernel is verified — the unfixed version crashes the box.

## Key references
- Crash/fix detail: `memory/m4-lock-mismatch-crash.md`
- Full plan (M0–M5): `~/.claude/plans/the-main-goal-is-wild-cake.md`
- BPF DS library: `policies/cache_ext_ds.bpf.h`
