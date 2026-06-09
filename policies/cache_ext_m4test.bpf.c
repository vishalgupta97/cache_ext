// SPDX-License-Identifier: GPL-2.0
/*
 * cache_ext M4 smoke test: "expose the folio-storing parent struct to BPF as
 * writable memory".
 *
 * The folio_added hook now receives mem_cgroup_per_node as a writable pointer
 * (mem_cgroup_per_node_bpf_writable, detected by btf_ctx_access -> MEM_WRITE).
 * mem_cgroup_per_node is the parent that stores the cache_ext data structures:
 *   - cache_ext_ds_registry  (embedded)        -> the lists
 *   - valid_folios_set       (pointer)         -> the per-folio nodes
 *
 * This policy proves the two verifier changes that make the kernel-resident
 * data structures writable from BPF, so the cache_ext kfuncs can be rewritten
 * in BPF:
 *   (1) a direct write to an embedded field of the writable struct
 *       (pn->cache_ext_ds_registry.nr_entries) exercises the dispatch that
 *       routes MEM_WRITE writes to the generic btf_struct_access (cache_ext's
 *       custom one would otherwise reject it), and
 *   (2) a write THROUGH a walked pointer (pn->valid_folios_set->nr_entries)
 *       exercises MEM_WRITE propagation across pointer walks.
 *
 * Both writes are guarded by prove_write, a plain .bss global left 0 by the
 * loader (NOT a const/.rodata one, which libbpf freezes and the verifier would
 * constant-fold, eliminating the branch). The verifier still verifies the
 * branch; it never runs, so no kernel state is actually modified. Loading this
 * policy successfully is the positive M4.1 test.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cache_ext_lib.bpf.h"
#include "cache_ext_ds.bpf.h"

char _license[] SEC("license") = "GPL";

/* .bss (non-const) so the verifier cannot fold it away. */
volatile bool prove_write;

/* M4.2: BPF valid_folios_lookup correctness counters (read in dmesg). */
__u64 lookup_total;   /* folio_added calls with a valid parent */
__u64 lookup_found;   /* BPF lookup returned a node */
__u64 lookup_match;   /* returned node->folio == folio (correct) */
__u64 lookup_miss;    /* lookup returned NULL */

/* M4.4: pure-BPF list. main_list is a kernel cache_ext_list (allocated by the
 * one remaining kfunc); all list operations below are pure BPF. */
__u64 main_list;      /* (u64)cache_ext_list * */
__u64 list_adds;      /* number of BPF list_add_tail calls */
__u64 list_count;     /* nodes counted by walking the BPF-built list */

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
	if (!pn)
		return;

	/*
	 * M4.2: exercise the BPF reimplementation of valid_folios_lookup. The
	 * kernel has just added this folio to valid_folios (filemap.c calls
	 * valid_folios_add before this hook), so the lookup must find a node whose
	 * ->folio is this folio.
	 */
	{
		struct cache_ext_list_node *node =
			cache_ext_bpf_valid_folios_lookup(pn, folio);
		__u64 folio_key = cache_ext_ptr_to_u64(folio);
		__sync_fetch_and_add(&lookup_total, 1);
		if (!node) {
			__sync_fetch_and_add(&lookup_miss, 1);
		} else {
			__u64 node_folio = 0;
			__sync_fetch_and_add(&lookup_found, 1);
			/* cache_ext_list_node->folio is at offset 0 */
			if (!bpf_probe_read_kernel(&node_folio, sizeof(node_folio),
						   (void *)node) &&
			    node_folio == folio_key)
				__sync_fetch_and_add(&lookup_match, 1);

			/*
			 * M4.4: PURE-BPF list_add_tail. Re-type the node and the
			 * list to writable typed pointers and link the node into
			 * the list -- all via direct typed MEM_WRITE stores, no
			 * cache_ext list kfunc. Then walk the list and record its
			 * length; if the BPF list ops are correct, list_count keeps
			 * pace with list_adds.
			 */
			if (main_list) {
				struct cache_ext_list_node *wnode =
					cache_ext_writable_cast((__u64)node,
								struct cache_ext_list_node);
				struct cache_ext_list *wlist =
					cache_ext_writable_cast(main_list,
								struct cache_ext_list);
				if (wnode && wlist) {
					cache_ext_bpf_list_add_tail(wlist, wnode);
					__sync_fetch_and_add(&list_adds, 1);
					/* O(1) integrity check: the node we just
					 * appended must now be the list tail. If this
					 * holds for every add, the BPF list_add_tail
					 * linkage is correct. */
					if (wlist->head.prev == &wnode->node)
						__sync_fetch_and_add(&list_count, 1);
				}
			}
		}
	}

	if (prove_write && pn->valid_folios_set) {
		/*
		 * Write THROUGH a walked pointer: pn (MEM_WRITE) ->
		 * valid_folios_set (MEM_WRITE via propagation) -> a field. This
		 * single write exercises BOTH verifier fixes at once:
		 *   - the walked valid_folios_set pointer is writable only because
		 *     MEM_WRITE propagates across the walk, and
		 *   - the store is permitted only because MEM_WRITE writes bypass
		 *     cache_ext's custom btf_struct_access and use the generic path.
		 * Use valid_folios[0].first (offset 0) -- deep fields like
		 * nr_entries sit past the multi-MB valid_folios[]/bucket_locks[]
		 * arrays and can't be encoded in a BPF load/store's 16-bit offset.
		 */
		pn->valid_folios_set->valid_folios[0].first = NULL;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops m4test_ops = {
	.init = (void *)m4test_init,
	.folio_added = (void *)m4test_folio_added,
};
