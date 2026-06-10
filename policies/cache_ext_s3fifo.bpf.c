// SPDX-License-Identifier: GPL-2.0
/*
 * S3-FIFO eviction policy -- PURE BPF data structures (M4).
 *
 * Two FIFO queues (small + main) plus a ghost map. List maintenance is pure BPF
 * over the kernel-resident nodes:
 *   folio_added  -> cache_ext_list_add_tail_bpf (small or main, by ghost hit)
 *   folio_evicted-> ghost insert + metadata delete + cache_ext_list_del_bpf
 *   folio_accessed-> freq++ (capped at 3), no list op
 * The only kfunc is new_list (in init).
 *
 * evict_folios is a FAITHFUL reimplementation of the kernel
 * cache_ext_list_iterate_extended op: it walks the list from the head (bpf_loop,
 * bound == kernel max_iter 4096) under the policy bpf_spin_lock held across the
 * ENTIRE walk -- a single critical section, exactly matching the kernel holding
 * the registry write_lock -- scores each node, and *moves* nodes (list_move_tail)
 * to a continue/evict list as it goes, with list_for_each_entry_safe semantics
 * (the successor is read before the move). The v7.0 spin-lock timeout + undo
 * logging make this long-held lock on the reclaim path safe.
 *
 * Making this branchy bpf_loop converge under the verifier took TWO things:
 *
 *  1. Kernel verifier change (cs_write_count): a bpf_loop callback running inside
 *     a spin-lock critical section accumulates one undo-logged write per node, so
 *     cs_write_count grows monotonically and the states_equal gate that rejects a
 *     lower-write cached state never lets the loop-entry checkpoint match. The
 *     gate is relaxed for the pruning comparisons (NOT_EXACT/RANGE_WITHIN),
 *     keeping it only for EXACT (infinite-loop detection); the per-write undo-log
 *     cap still backstops it. (kernel verifier.c states_equal.)
 *
 *  2. The running victim count lives in a per-cpu MAP, NOT the bpf_loop ctx. A
 *     self-incremented counter that is also used as a map key gets marked PRECISE,
 *     and precise scalars are never widened across iterations, so carried in the
 *     ctx it made every iteration's state distinct (combinatorially, via the
 *     EVICT/CONTINUE branch) and the walk exploded the 1M-insn limit. See
 *     s3_evict_cnt. (The unbounded nr_continue counter, by contrast, stays in the
 *     ctx fine -- it is never a map key, so it is widened, exactly like the
 *     sampling policy's ctx count.)
 *
 * Evicted folios cannot be written into ctx->folios_to_evict[nr] from inside the
 * loop (a runtime index into the ctx BTF array is rejected by the verifier), so
 * they are buffered in a per-cpu scratch array indexed by the running count and
 * copied into the ctx at constant indices after the walk.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "cache_ext_ds.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define ENOENT		2  /* include/uapi/asm-generic/errno-base.h */
#define INT64_MAX	(9223372036854775807LL)

// Set from userspace. In terms of number of pages.
#define CACHE_SIZE (((1ull << 20) * 200) / 4096)
const volatile size_t cache_size = 0;

#define S3_EVICT_MAX	32     /* == ARRAY_SIZE(ctx->folios_to_evict) */


#define SCORER_SMALL	0
#define SCORER_MAIN	1

struct folio_metadata {
	s64 freq;
	bool in_main;
};

struct ghost_entry {
	u64 address_space;
	u64 offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ghost_entry);
	__type(value, u8);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);  // Per-CPU LRU eviction logic
} ghost_map SEC(".maps");

/* Buffer of victim folios filled during the walk (runtime-indexed); flushed to
 * the eviction ctx at constant indices afterwards. */
struct s3_scratch_val {
	__u64 folio;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, S3_EVICT_MAX);
	__type(key, __u32);
	__type(value, struct s3_scratch_val);
} s3_evict_scratch SEC(".maps");

/*
 * Running victim count for the current evict_folios call. Kept in a per-cpu MAP
 * (not the bpf_loop ctx) on purpose: a self-incremented counter that is also used
 * as the s3_evict_scratch key gets marked PRECISE by the verifier, and a precise
 * scalar is never widened across bpf_loop iterations (maybe_widen_reg skips
 * precise regs). Carried in the ctx it makes every iteration's state distinct
 * (combinatorially, via the EVICT/CONTINUE branch) -> the walk never converges
 * and explodes the 1M-insn limit. A map-resident counter is re-read fresh each
 * iteration, so it is not part of the loop-carried register state the verifier
 * must converge -- mirroring how the sampling policy reads sample_results. The
 * value persists across the 4 main passes within one evict_folios call.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} s3_evict_cnt SEC(".maps");

static __always_inline __u32 *s3_cnt(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&s3_evict_cnt, &k);
}

static u64 main_list;
static u64 small_list;

/*
 * This is an approximate value based on what we choose to evict, not what is
 * actually evicted.
 */
static s64 small_list_size = 0;
static s64 main_list_size = 0;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

static inline struct folio_metadata *get_folio_metadata(struct folio *folio) {
	u64 key = (u64)folio;
	return bpf_map_lookup_elem(&folio_metadata_map, &key);
}

/*
 * Check if a folio is in the ghost map and delete the ghost entry.
 * We only check if an element is in the ghost map on inserting into the cache.
 * Relies on bpf_map_delete_elem() returning -ENOENT if the element is not found.
 */
static inline bool folio_in_ghost(struct folio *folio) {
	struct ghost_entry key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};
	// TODO: handle non-ENOENT errors
	return bpf_map_delete_elem(&ghost_map, &key) != -ENOENT;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(s3fifo_init, struct mem_cgroup *memcg)
{
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: init: Failed to create main_list\n");
		return -1;
	}

	small_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (small_list == 0) {
		bpf_printk("cache_ext: init: Failed to create small_list\n");
		return -1;
	}

	return 0;
}

/*
 * Score a folio addressed by `folio` (raw kernel address). Mirrors the kernel
 * iterate scorers: non-reclaimable folios CONTINUE (stay/promote, never evict),
 * the SMALL scorer evicts unless freq > 1 (then promote to main), the MAIN
 * scorer decrements freq and evicts once it drops below the pass threshold.
 */
static __always_inline int s3_decide(__u64 folio, __u32 scorer, __s64 threshold)
{
	struct folio_metadata *data;
	__u64 key = folio, flags = 0;

	/* folio->flags is at offset 0 of struct folio. */
	if (bpf_probe_read_kernel(&flags, sizeof(flags), (void *)folio))
		return CACHE_EXT_CONTINUE_ITER;
	if (!(flags & (1UL << PG_uptodate)) || !(flags & (1UL << PG_lru)))
		return CACHE_EXT_CONTINUE_ITER;
	if ((flags & (1UL << PG_dirty)) || (flags & (1UL << PG_writeback)))
		return CACHE_EXT_CONTINUE_ITER;

	data = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!data)
		return CACHE_EXT_CONTINUE_ITER;

	if (scorer == SCORER_SMALL) {
		/* Promote to main if accessed more than once, else evict. */
		if (data->freq > 1) {
			data->in_main = true;
			return CACHE_EXT_CONTINUE_ITER;
		}
		return CACHE_EXT_EVICT_NODE;
	}

	/* MAIN: age by one and evict once below the pass threshold. */
	if (__sync_sub_and_fetch(&data->freq, 1) < threshold)
		return CACHE_EXT_EVICT_NODE;
	return CACHE_EXT_CONTINUE_ITER;
}

/*
 * State for one iterate_extended pass. `head`/`cur` track the walk; the move
 * targets are list ids (== &list->head); the counters accumulate ACROSS passes
 * (the kernel's evict_main_iter appends to the same ctx over 4 passes).
 */
struct s3_iter_ctx {
	__u64 head;          /* &list->head of the list being walked */
	__u64 cur;           /* current node's list_head address */
	__u64 continue_list; /* list id to move CONTINUE nodes to (tail) */
	__u64 evict_list;    /* list id to move EVICT nodes to (tail) */
	__u32 scorer;        /* SCORER_SMALL / SCORER_MAIN */
	__s64 threshold;     /* MAIN pass id */
	__u64 nr_continue;   /* running continue/promote count (accounting) */
	bool  full;          /* scratch/ctx array filled -> stop */
};

#define S3_MAX_ITER 4096   /* == kernel iterate_extended max_iter */

/*
 * Move a node (at node_addr) to the tail of target_id. The policy bpf_spin_lock
 * is already held by the caller (s3_iterate_pass holds it across the whole
 * walk -- a single critical section, exactly like the kernel iterate_extended
 * holding the registry write_lock). The "still-linked" gate skips a node that a
 * concurrent folio_evicted has already list_del_init'd (next == &node->node), so
 * we never re-link a node that is being freed.
 */
static __always_inline void s3_move_node(__u64 node_addr, __u64 target_id)
{
	struct cache_ext_list_node *wnode;
	struct cache_ext_list *wtgt;
	__u64 self;

	wnode = cache_ext_writable_cast(node_addr, struct cache_ext_list_node);
	wtgt = cache_ext_writable_cast(target_id, struct cache_ext_list);
	if (!wnode || !wtgt)
		return;

	self = node_addr + 8; /* &node->node (list_head @8) */
	if (cache_ext_ptr_to_u64(wnode->node.next) != self) {
		cache_ext_bpf_list_del(wnode);
		cache_ext_bpf_list_add_tail(wtgt, wnode);
	}
}

/*
 * bpf_loop callback: one step of list_for_each_entry_safe over the kernel list.
 * Offsets: cache_ext_list_node { folio @0; list_head node @8 }, list_head.next
 * @0. The successor (`next`) is read BEFORE the node is moved (so moving the
 * node, even to the tail of the same list, does not corrupt the walk). Runs with
 * the policy lock held by s3_iterate_pass. Returns 1 to stop, 0 to continue.
 */
static int s3_iter_cb(__u32 i, void *vctx)
{
	struct s3_iter_ctx *c = vctx;
	__u64 node_addr, folio = 0, next = 0;
	int decision;

	if (c->full)
		return 1;
	if (c->cur == 0 || c->cur == c->head)
		return 1; /* reached the head -> done */

	node_addr = c->cur - 8; /* container_of(cur, cache_ext_list_node, node) */
	if (bpf_probe_read_kernel(&folio, sizeof(folio), (void *)node_addr))
		return 1;
	/* node2 = node->next, read before any move (list_for_each_entry_safe). */
	if (bpf_probe_read_kernel(&next, sizeof(next), (void *)c->cur))
		return 1;

	decision = s3_decide(folio, c->scorer, c->threshold);

	if (decision == CACHE_EXT_EVICT_NODE) {
		__u32 *cnt = s3_cnt();
		__u32 idx;

		if (!cnt)
			return 1;
		idx = *cnt;
		if (idx < S3_EVICT_MAX) {
			struct s3_scratch_val *sv =
				bpf_map_lookup_elem(&s3_evict_scratch, &idx);
			if (sv)
				sv->folio = folio;
			*cnt = idx + 1;
		}
		s3_move_node(node_addr, c->evict_list);
		if (idx + 1 >= S3_EVICT_MAX) {
			c->full = true;
			c->cur = next;
			return 1;
		}
	} else if (decision == CACHE_EXT_CONTINUE_ITER) {
		s3_move_node(node_addr, c->continue_list);
		c->nr_continue++;
	} else {
		return 1; /* STOP (unused by s3fifo scorers) */
	}

	c->cur = next;
	return 0;
}

/*
 * Run one iterate_extended pass over c->head, holding the policy bpf_spin_lock
 * across the entire bpf_loop walk -- a single critical section matching the
 * kernel's registry write_lock. Counters in `c` accumulate so the caller can
 * chain passes (the kernel's 4 main passes).
 *
 * NOTE: this requires verifier support for state merging / loop convergence of a
 * bpf_loop whose callback runs inside a spin-lock critical section. On a stock
 * verifier the lock CS disables state pruning and the walk explodes the
 * jump-sequence / state-count complexity limits; the v7.0 spin-lock
 * timeout + undo-logging make the long-held lock safe at runtime, and the
 * matching verifier change makes it tractable to verify.
 */
static __always_inline void s3_iterate_pass(struct s3_iter_ctx *c)
{
	struct bpf_spin_lock *lk = cache_ext_lock();
	__u64 first = 0;

	if (!c->head || c->full || !lk)
		return;

	bpf_spin_lock(lk);
	bpf_probe_read_kernel(&first, sizeof(first), (void *)c->head); /* head.next */
	c->cur = first;
	bpf_loop(S3_MAX_ITER, s3_iter_cb, c, 0);
	bpf_spin_unlock(lk);
}

static __always_inline void
s3_run_pass(__u64 list_id, __u64 continue_list, __u64 evict_list,
	    __u32 scorer, __s64 threshold, struct s3_iter_ctx *c)
{
	c->head = list_id;
	c->continue_list = continue_list;
	c->evict_list = evict_list;
	c->scorer = scorer;
	c->threshold = threshold;
	s3_iterate_pass(c);
}

/* Copy the buffered victims into the eviction ctx at constant indices. */
static __always_inline void
s3_flush_scratch(struct cache_ext_eviction_ctx *ectx, __u32 nr)
{
	int i;

	if (nr > S3_EVICT_MAX)
		nr = S3_EVICT_MAX;
	for (i = 0; i < S3_EVICT_MAX; i++) {
		struct s3_scratch_val *sv;
		__u32 k = i;

		if ((__u32)i >= nr)
			break;
		sv = bpf_map_lookup_elem(&s3_evict_scratch, &k);
		if (!sv || !sv->folio)
			break;
		ectx->folios_to_evict[i] = (struct folio *)sv->folio;
	}
	ectx->nr_folios_to_evict = nr;
}

/*
 * Iterate the small list: promote (freq > 1) to the tail of main, otherwise
 * evict (move to the tail of small in the meantime). continue_list = main,
 * evict_list = small (self).
 */
static void evict_small(struct cache_ext_eviction_ctx *ectx)
{
	struct s3_iter_ctx c = {};
	__u32 *cnt = s3_cnt();

	if (cnt)
		*cnt = 0; /* reset victim count for this evict_folios call */

	s3_run_pass(small_list, /*continue*/ main_list, /*evict*/ small_list,
			SCORER_SMALL, 0, &c);

	if (__sync_fetch_and_sub(&small_list_size, c.nr_continue) < 0)
		small_list_size = 0;
	if (__sync_fetch_and_add(&main_list_size, c.nr_continue) < 0)
		main_list_size = c.nr_continue;

	cnt = s3_cnt();
	s3_flush_scratch(ectx, cnt ? *cnt : 0);
}

/*
 * Iterate the main list in up to 4 ascending-threshold passes, each decrementing
 * freq and evicting nodes that fall below the threshold; continue/evict both move
 * to the tail of main (self). Stop early once the request is met.
 */
static void evict_main_iter(struct cache_ext_eviction_ctx *ectx)
{
	struct s3_iter_ctx c = {};
	unsigned long req = ectx->request_nr_folios_to_evict;
	__u32 *cnt = s3_cnt();

	if (cnt)
		*cnt = 0; /* reset victim count for this evict_folios call */

	s3_run_pass(main_list, main_list, main_list, SCORER_MAIN, 0, &c);
	cnt = s3_cnt();
	if (cnt && *cnt < req)
		s3_run_pass(main_list, main_list, main_list, SCORER_MAIN, 1, &c);
	cnt = s3_cnt();
	if (cnt && *cnt < req)
		s3_run_pass(main_list, main_list, main_list, SCORER_MAIN, 2, &c);
	cnt = s3_cnt();
	if (cnt && *cnt < req)
		s3_run_pass(main_list, main_list, main_list, SCORER_MAIN, 3, &c);

	cnt = s3_cnt();
	s3_flush_scratch(ectx, cnt ? *cnt : 0);
}

void BPF_STRUCT_OPS(s3fifo_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (small_list_size >= cache_size / 15 || main_list_size <= 2 * small_list_size)
		evict_small(eviction_ctx);
	else
		evict_main_iter(eviction_ctx);
}

void BPF_STRUCT_OPS(s3fifo_folio_accessed, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	struct folio_metadata *data = get_folio_metadata(folio);
	if (!data)
		return;

	// Cap frequency at 3
	if (__sync_add_and_fetch(&data->freq, 1) > 3)
		data->freq = 3;
}

void BPF_STRUCT_OPS(s3fifo_folio_evicted, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn) {
	u64 key = (u64)folio;
	u8 ghost_val = 0;
	struct ghost_entry ghost_key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};
	struct folio_metadata *data;

	// Don't return early, we want to delete the folio metadata regardless
	if (bpf_map_update_elem(&ghost_map, &ghost_key, &ghost_val, BPF_ANY))
		bpf_printk("cache_ext: evicted: Failed to add to ghost_map\n");

	data = get_folio_metadata(folio);
	if (data) {
		if (data->in_main)
			__sync_fetch_and_sub(&main_list_size, 1);
		else
			__sync_fetch_and_sub(&small_list_size, 1);
	}

	/* Delete metadata FIRST (liveness marker), then unlink the node before the
	 * kernel frees it. The eviction walk treats a node with no metadata as
	 * non-evictable, so a racing walk never offers a folio being torn down. */
	bpf_map_delete_elem(&folio_metadata_map, &key);
	cache_ext_list_del_bpf(pn, folio);
}

/*
 * If folio is in the ghost map, add to tail of main list, otherwise add to tail
 * of small list.
 */
void BPF_STRUCT_OPS(s3fifo_folio_added, struct folio *folio,
		    mem_cgroup_per_node_bpf_writable *pn) {
	u64 key = (u64)folio;
	struct folio_metadata new_meta = {
		.freq = 0,
	};
	u64 list_to_add;

	if (!is_folio_relevant(folio))
		return;

	if (folio_in_ghost(folio)) {
		list_to_add = main_list;
		new_meta.in_main = true;
		__sync_fetch_and_add(&main_list_size, 1);
	} else {
		list_to_add = small_list;
		new_meta.in_main = false;
		__sync_fetch_and_add(&small_list_size, 1);
	}

	if (cache_ext_list_add_tail_bpf(pn, folio, list_to_add)) {
		bpf_printk("cache_ext: added: Failed to add folio to list\n");
		return;
	}

	if (bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY)) {
		cache_ext_list_del_bpf(pn, folio);
		bpf_printk("cache_ext: added: Failed to create folio metadata\n");
		return;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops s3fifo_ops = {
	.init = (void *)s3fifo_init,
	.evict_folios = (void *)s3fifo_evict_folios,
	.folio_accessed = (void *)s3fifo_folio_accessed,
	.folio_evicted = (void *)s3fifo_folio_evicted,
	.folio_added = (void *)s3fifo_folio_added,
};
