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

char _license[] SEC("license") = "GPL";

/* .bss (non-const) so the verifier cannot fold it away. */
volatile bool prove_write;

s32 BPF_STRUCT_OPS_SLEEPABLE(m4test_init, struct mem_cgroup *memcg)
{
	return 0;
}

void BPF_STRUCT_OPS(m4test_folio_added, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	if (!pn)
		return;

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
