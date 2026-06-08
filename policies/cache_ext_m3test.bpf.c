// SPDX-License-Identifier: GPL-2.0
/*
 * cache_ext M3 test policy: "expose folios through the verifier".
 *
 * Functionally a minimal FIFO, but its eviction callback exercises the M3
 * kernel change: the struct cache_ext_list_node * handed to iterate/sample
 * callbacks is now PTR_TRUSTED, and node->folio is tagged BTF_TYPE_SAFE_TRUSTED,
 * so walking node->folio yields a *trusted* folio. The cache_ext list kfuncs
 * require their struct folio * argument to be verifier-trusted (this tree
 * enforces is_trusted_reg() for all KF_ARG_PTR_TO_BTF_ID kfunc args), so the
 * guarded bpf_cache_ext_list_del(a->folio) below only verifies because of the
 * M3 change. Without it the program is rejected at load with
 * "R1 must be referenced or trusted".
 *
 * The call is guarded by prove_trusted_folio, a const volatile flag left 0 by
 * the loader: the verifier still checks the branch (the value is unknown at
 * verification time) but it never executes at runtime, so iteration is not
 * mutated. Loading this policy successfully *is* the positive M3 test.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 main_list;

/*
 * Plain (non-const) global -> lives in .bss, which libbpf does NOT freeze, so
 * the verifier cannot constant-fold it and MUST verify the guarded branch.
 * (A const volatile in .rodata would be frozen and the branch dead-code
 * eliminated, making the test vacuous.) volatile forces clang to emit the load.
 * Left 0 at runtime, so the guarded call never actually executes.
 */
volatile bool prove_trusted_folio;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(m3test_init, struct mem_cgroup *memcg)
{
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: m3test init: Failed to create main_list\n");
		return -1;
	}
	return 0;
}

static int m3test_evict_cb(int idx, struct cache_ext_list_node *a)
{
	/* Verifier-checked typed reads of a trusted folio's fields. */
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	/*
	 * M3 proof: a->folio is verifier-TRUSTED. Passing it to a cache_ext kfunc
	 * (which mandates trusted btf_id args) only verifies because of the
	 * node->folio BTF_TYPE_SAFE_TRUSTED tagging. Never executed (guard is 0).
	 */
	if (prove_trusted_folio)
		bpf_cache_ext_list_del(a->folio);

	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(m3test_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (bpf_cache_ext_list_iterate(memcg, main_list, m3test_evict_cb, eviction_ctx) < 0) {
		bpf_printk("cache_ext: m3test evict: Failed to iterate main_list\n");
		return;
	}
}

void BPF_STRUCT_OPS(m3test_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	if (bpf_cache_ext_list_add_tail(main_list, folio)) {
		bpf_printk("cache_ext: m3test added: Failed to add folio to main_list\n");
		return;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops m3test_ops = {
	.init = (void *)m3test_init,
	.evict_folios = (void *)m3test_evict_folios,
	.folio_added = (void *)m3test_folio_added,
};
