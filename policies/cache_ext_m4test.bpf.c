// SPDX-License-Identifier: GPL-2.0
/*
 * cache_ext M4 test: pure-BPF list over kernel-resident nodes, with locking and
 * eviction-safe teardown.
 *
 * The folio hooks receive mem_cgroup_per_node as a writable pointer
 * (mem_cgroup_per_node_bpf_writable). main_list is a kernel cache_ext_list
 * (allocated by the one remaining kfunc, new_list); everything else is BPF:
 *   - folio_added:   BPF valid_folios lookup -> writable cast -> list_add_tail
 *   - folio_evicted: BPF valid_folios lookup -> writable cast -> list_del
 *     (list_del_init), so the node is OUT of the list before the kernel frees
 *     it in valid_folios_del (the hook runs first; see filemap.c). The kernel's
 *     own list_del then operates on a self-referential node -> harmless.
 *
 * A bpf_spin_lock serialises the list mutations across CPUs (concurrent
 * folio_added from multi-CPU readahead would otherwise corrupt the list). The
 * lookups run OUTSIDE the lock (they call helpers / loop, which isn't allowed
 * under bpf_spin_lock); only the straight-line list linkage runs under it.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cache_ext_lib.bpf.h"
#include "cache_ext_ds.bpf.h"

char _license[] SEC("license") = "GPL";

/* valid_folios lookup correctness counters. */
__u64 lookup_total;
__u64 lookup_found;
__u64 lookup_match;
__u64 lookup_miss;

/* pure-BPF list activity. */
__u64 main_list;      /* (u64)cache_ext_list * */
__u64 list_adds;
__u64 list_dels;
__u64 evict_calls;    /* evict_folios invocations */
__u64 evict_victims;  /* folios offered for eviction */

/* Lock protecting the BPF list operations. */
struct ce_lock {
	struct bpf_spin_lock lock;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ce_lock);
} list_lock SEC(".maps");

static __always_inline struct ce_lock *ce_get_lock(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&list_lock, &k);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(m4test_init, struct mem_cgroup *memcg)
{
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0)
		return -1;
	return 0;
}

void BPF_STRUCT_OPS(m4test_folio_added, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	struct cache_ext_list_node *node, *wnode;
	struct cache_ext_list *wlist;
	struct ce_lock *l;
	__u64 node_folio = 0;

	if (!pn || !main_list)
		return;

	/* lookup + correctness check, outside the lock */
	node = cache_ext_bpf_valid_folios_lookup(pn, folio);
	__sync_fetch_and_add(&lookup_total, 1);
	if (!node) {
		__sync_fetch_and_add(&lookup_miss, 1);
		return;
	}
	__sync_fetch_and_add(&lookup_found, 1);
	if (!bpf_probe_read_kernel(&node_folio, sizeof(node_folio), (void *)node) &&
	    node_folio == cache_ext_ptr_to_u64(folio))
		__sync_fetch_and_add(&lookup_match, 1);

	wnode = cache_ext_writable_cast((__u64)node, struct cache_ext_list_node);
	wlist = cache_ext_writable_cast(main_list, struct cache_ext_list);
	l = ce_get_lock();
	if (!wnode || !wlist || !l)
		return;

	/* pure-BPF list_add_tail under the lock (straight-line, no calls) */
	bpf_spin_lock(&l->lock);
	cache_ext_bpf_list_add_tail(wlist, wnode);
	bpf_spin_unlock(&l->lock);
	__sync_fetch_and_add(&list_adds, 1);
}

/*
 * Pure-BPF FIFO eviction: walk main_list from the head (oldest first) and hand
 * the kernel up to request_nr_folios_to_evict victims. The whole walk runs under
 * the bpf_spin_lock so concurrent folio_added/evicted cannot free a node mid-walk
 * (-> no use-after-free / garbage folio offered to the kernel). The list is
 * traversed with bpf_probe_read_kernel (allowed under bpf_spin_lock; it is not a
 * sleepable helper) over raw addresses:
 *   cache_ext_list.head      @ 0  -> &list->head == main_list
 *   list_head.next           @ 0
 *   cache_ext_list_node.node @ 8  -> node = list_head_addr - 8
 *   cache_ext_list_node.folio@ 0
 * The loop is unrolled (bound 32 = folios_to_evict size) so the array index is a
 * compile-time constant (a variable index into the ctx BTF struct is rejected).
 * No evictability filtering -- pure FIFO; the kernel skips folios it can't reclaim.
 */
#define CACHE_EXT_EVICT_MAX 32

void BPF_STRUCT_OPS(m4test_evict_folios, struct cache_ext_eviction_ctx *ectx,
		    struct mem_cgroup *memcg)
{
	struct ce_lock *l;
	__u64 head_addr, cur = 0;
	unsigned long req, k = 0;
	int i;

	__sync_fetch_and_add(&evict_calls, 1);  /* count entry, before any bail-out */
	if (!main_list)
		return;
	l = ce_get_lock();
	if (!l)
		return;

	req = ectx->request_nr_folios_to_evict;
	head_addr = main_list; /* &list->head (head is at offset 0) */

	bpf_spin_lock(&l->lock);
	bpf_probe_read_kernel(&cur, sizeof(cur), (void *)head_addr); /* head.next */
	for (i = 0; i < CACHE_EXT_EVICT_MAX; i++) {
		__u64 node_addr, folio = 0;

		if (cur == 0 || cur == head_addr)
			break;
		if ((unsigned long)i >= req)
			break;
		node_addr = cur - 8; /* container_of(cur, cache_ext_list_node, node) */
		bpf_probe_read_kernel(&folio, sizeof(folio), (void *)node_addr);
		ectx->folios_to_evict[i] = (struct folio *)folio; /* const index i */
		k++;
		bpf_probe_read_kernel(&cur, sizeof(cur), (void *)cur); /* next */
	}
	ectx->nr_folios_to_evict = k;
	bpf_spin_unlock(&l->lock);
	__sync_fetch_and_add(&evict_victims, k);
}

void BPF_STRUCT_OPS(m4test_folio_evicted, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	struct cache_ext_list_node *node, *wnode;
	struct ce_lock *l;

	if (!pn || !main_list)
		return;

	/* Unlink the node BEFORE the kernel frees it (valid_folios_del runs after
	 * this hook). lookup outside the lock. */
	node = cache_ext_bpf_valid_folios_lookup(pn, folio);
	if (!node)
		return;
	wnode = cache_ext_writable_cast((__u64)node, struct cache_ext_list_node);
	l = ce_get_lock();
	if (!wnode || !l)
		return;

	bpf_spin_lock(&l->lock);
	cache_ext_bpf_list_del(wnode);
	bpf_spin_unlock(&l->lock);
	__sync_fetch_and_add(&list_dels, 1);
}

SEC(".struct_ops.link")
struct cache_ext_ops m4test_ops = {
	.init = (void *)m4test_init,
	.evict_folios = (void *)m4test_evict_folios,
	.folio_added = (void *)m4test_folio_added,
	.folio_evicted = (void *)m4test_folio_evicted,
};
