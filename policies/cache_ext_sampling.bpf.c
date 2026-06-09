// SPDX-License-Identifier: GPL-2.0
/*
 * Sampling (LFU-ish) eviction policy -- PURE BPF data structures (M4).
 *
 * List maintenance is pure BPF over the kernel-resident nodes (folio_added
 * appends, folio_evicted unlinks before the kernel frees the node). The only
 * kfunc is new_list. evict_folios reimplements the kernel `sample` op in BPF:
 * walk the head of the list, score each folio (LFU: access count, plus
 * non-evictable folios get INT64_MAX), and for each group of sample_size folios
 * evict the lowest-scoring one.
 *
 * The walk is a racy bpf_loop walk over raw addresses (bpf_probe_read_kernel) --
 * NOT under the bpf_spin_lock, because bpf_loop is not allowed inside a
 * spin-lock CS. Safety: a folio that has been (or is being) evicted has its
 * metadata deleted FIRST in folio_evicted, and its node unlinked, so the walk
 * only reaches live folios; any stale/freed node has no metadata and scores
 * INT64_MAX, so it is never offered to the kernel. evict_folios is only invoked
 * under real LRU reclaim (MGLRU off, working-set workload), not streaming reads.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "cache_ext_ds.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define INT64_MAX (9223372036854775807LL)
#define SAMPLE_SIZE 20
#define EVICT_MAX 32

struct folio_metadata {
	u64 accesses;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

/* per-CPU per-group running minimum used while sampling. */
struct sample_min {
	__u64 folio;
	__s64 score;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EVICT_MAX);
	__type(key, __u32);
	__type(value, struct sample_min);
} sample_results SEC(".maps");

__u64 sampling_list;

static inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;
	return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sampling_init, struct mem_cgroup *memcg)
{
	sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (sampling_list == 0)
		return -1;
	return 0;
}

void BPF_STRUCT_OPS(sampling_folio_added, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	u64 key = (u64)folio;
	struct folio_metadata new_meta = { .accesses = 1 };

	if (!is_folio_relevant(folio))
		return;
	if (cache_ext_list_add_tail_bpf(pn, folio, sampling_list))
		return;
	bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
}

void BPF_STRUCT_OPS(sampling_folio_accessed, struct folio *folio)
{
	struct folio_metadata *meta;
	u64 key = (u64)folio;

	if (!is_folio_relevant(folio))
		return;
	meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta) {
		struct folio_metadata new_meta = { 0 };

		if (bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY))
			return;
		meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
		if (!meta)
			return;
	}
	__sync_fetch_and_add(&meta->accesses, 1);
}

void BPF_STRUCT_OPS(sampling_folio_evicted, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn)
{
	u64 key = (u64)folio;

	/* Delete metadata FIRST (liveness marker), then unlink the node before
	 * the kernel frees it. */
	bpf_map_delete_elem(&folio_metadata_map, &key);
	cache_ext_list_del_bpf(pn, folio);
}

/* Page-flag bits we care about (vmlinux enum pageflags). */
static __always_inline __s64 sampling_score(__u64 folio_addr)
{
	struct folio_metadata *meta;
	__u64 key = folio_addr;
	__u64 flags = 0;
	__s64 score;

	meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta)
		return INT64_MAX; /* not live / already evicted */
	score = meta->accesses;

	/* folio->flags.f is at offset 0 of struct folio */
	if (bpf_probe_read_kernel(&flags, sizeof(flags), (void *)folio_addr))
		return INT64_MAX;
	if (!(flags & (1UL << PG_uptodate)) || !(flags & (1UL << PG_lru)))
		return INT64_MAX;
	if ((flags & (1UL << PG_dirty)) || (flags & (1UL << PG_writeback)))
		return INT64_MAX;
	return score;
}

struct sample_walk_ctx {
	__u64 cur;   /* current list_head address */
	__u64 head;  /* &list->head */
	__u64 count; /* nodes actually visited */
};

static int sample_walk_cb(__u32 i, void *vctx)
{
	struct sample_walk_ctx *c = vctx;
	__u64 node_addr, folio = 0, next = 0;
	__u32 group = i / SAMPLE_SIZE;
	struct sample_min *res;
	__s64 score;

	if (c->cur == 0 || c->cur == c->head)
		return 1; /* end of list */
	node_addr = c->cur - 8; /* container_of(cur, cache_ext_list_node, node) */
	if (bpf_probe_read_kernel(&folio, sizeof(folio), (void *)node_addr))
		return 1;
	score = sampling_score(folio);

	res = bpf_map_lookup_elem(&sample_results, &group);
	if (res) {
		if ((i % SAMPLE_SIZE) == 0 || score < res->score) {
			res->score = score;
			res->folio = folio;
		}
	}
	c->count++;
	/* advance: cur = cur->next (list_head.next @ 0) */
	if (bpf_probe_read_kernel(&next, sizeof(next), (void *)c->cur))
		return 1;
	c->cur = next;
	return 0;
}

void BPF_STRUCT_OPS(sampling_evict_folios,
		    struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	struct sample_walk_ctx c = {};
	unsigned long req = eviction_ctx->request_nr_folios_to_evict;
	__u64 num;
	unsigned long out = 0;
	int g;

	if (!sampling_list)
		return;
	if (req > EVICT_MAX)
		req = EVICT_MAX;
	num = req * SAMPLE_SIZE;

	c.head = sampling_list; /* &list->head (head @ offset 0) */
	if (bpf_probe_read_kernel(&c.cur, sizeof(c.cur), (void *)c.head))
		return;

	bpf_loop(num, sample_walk_cb, &c, 0);

	/* Groups populate 0,1,2,... in order, so the populated groups are exactly
	 * [0, num_groups) -- contiguous, no gaps. Emit each group's min at its
	 * constant index (a variable index into the ctx BTF array is rejected).
	 * A group's min may be INT64_MAX (non-evictable folio); that's harmless --
	 * the kernel skips folios it cannot reclaim. We never emit a NULL folio. */
	__u64 num_groups = (c.count + SAMPLE_SIZE - 1) / SAMPLE_SIZE;

	for (g = 0; g < EVICT_MAX; g++) {
		struct sample_min *res;
		__u32 key = g;

		if ((unsigned long)g >= req || (__u64)g >= num_groups)
			break;
		res = bpf_map_lookup_elem(&sample_results, &key);
		if (!res || res->folio == 0)
			break;
		eviction_ctx->folios_to_evict[g] = (struct folio *)res->folio;
		eviction_ctx->scores[g] = res->score;
		out++;
	}
	eviction_ctx->nr_folios_to_evict = out;
}

SEC(".struct_ops.link")
struct cache_ext_ops sampling_ops = {
	.init = (void *)sampling_init,
	.evict_folios = (void *)sampling_evict_folios,
	.folio_accessed = (void *)sampling_folio_accessed,
	.folio_evicted = (void *)sampling_folio_evicted,
	.folio_added = (void *)sampling_folio_added,
};
