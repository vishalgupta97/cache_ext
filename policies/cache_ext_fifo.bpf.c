// SPDX-License-Identifier: GPL-2.0
/*
 * FIFO eviction policy -- PURE BPF data structures (M4).
 *
 * The folio list is maintained entirely in BPF over the kernel-resident nodes:
 * folio_added appends, folio_evicted unlinks (before the kernel frees the node),
 * evict_folios hands the kernel the oldest folios. The only kfunc used is
 * bpf_cache_ext_ds_registry_new_list (allocation); all list operations are the
 * pure-BPF helpers in cache_ext_ds.bpf.h (writable-cast + bpf_spin_lock).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "cache_ext_ds.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 main_list;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fifo_init, struct mem_cgroup *memcg)
{
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: fifo init: Failed to create main_list\n");
		return -1;
	}
	return 0;
}

void BPF_STRUCT_OPS(fifo_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	cache_ext_evict_fifo(eviction_ctx, main_list);
}

void BPF_STRUCT_OPS(fifo_folio_evicted, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	cache_ext_list_del_bpf(pn, folio);
}

void BPF_STRUCT_OPS(fifo_folio_added, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	if (!is_folio_relevant(folio))
		return;

	cache_ext_list_add_tail_bpf(pn, folio, main_list);
}

SEC(".struct_ops.link")
struct cache_ext_ops fifo_ops = {
	.init = (void *)fifo_init,
	.evict_folios = (void *)fifo_evict_folios,
	.folio_evicted = (void *)fifo_folio_evicted,
	.folio_added = (void *)fifo_folio_added,
};
