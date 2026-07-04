// SPDX-License-Identifier: GPL-2.0
/*
 * MRU eviction policy -- PURE BPF data structures (M4).
 *
 * Most-recently-used: the list is ordered with the most recently touched folio
 * at the head, and eviction takes from the head. The list is maintained entirely
 * in BPF over the kernel-resident nodes:
 *   folio_added    -> insert at head (new folio is the most recent)
 *   folio_accessed -> move to head   (touched folio becomes the most recent)
 *   folio_evicted  -> unlink (before the kernel frees the node)
 *   evict_folios   -> hand the kernel the head folios (the most recently used)
 * The only kfunc used is bpf_cache_ext_ds_registry_new_list (allocation); all
 * list operations are the pure-BPF helpers in cache_ext_ds.bpf.h.
 *
 * folio_accessed receives the writable parent node (mem_cgroup_per_node) as a
 * second arg (M4 kernel change), so the move can be done in BPF.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "cache_ext_ds.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 mru_list;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mru_init, struct mem_cgroup *memcg)
{
	mru_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (mru_list == 0) {
		bpf_printk("cache_ext: mru init: Failed to create mru_list\n");
		return -1;
	}
	cache_ext_ds_init_lock(memcg);
	return 0;
}

void BPF_STRUCT_OPS(mru_folio_added, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	if (!is_folio_relevant(folio))
		return;

	cache_ext_list_add_bpf(pn, folio, mru_list);
}

void BPF_STRUCT_OPS(mru_folio_accessed, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	if (!is_folio_relevant(folio))
		return;

	cache_ext_list_move_bpf(pn, folio, mru_list, false);
}

void BPF_STRUCT_OPS(mru_folio_evicted, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	cache_ext_list_del_bpf(pn, folio);
}

void BPF_STRUCT_OPS(mru_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	cache_ext_evict_fifo(eviction_ctx, mru_list);
}

SEC(".struct_ops.link")
struct cache_ext_ops mru_ops = {
	.init = (void *)mru_init,
	.evict_folios = (void *)mru_evict_folios,
	.folio_accessed = (void *)mru_folio_accessed,
	.folio_evicted = (void *)mru_folio_evicted,
	.folio_added = (void *)mru_folio_added,
};
