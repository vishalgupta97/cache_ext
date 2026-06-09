#ifndef _CACHE_EXT_DS_BPF_H
#define _CACHE_EXT_DS_BPF_H 1
/*
 * BPF reimplementation of the cache_ext kernel data-structure operations (M4).
 *
 * The kernel exposes mem_cgroup_per_node to the policy as a writable pointer
 * (mem_cgroup_per_node_bpf_writable). From it the policy reaches:
 *   pn->valid_folios_set : the per-folio hashtable (valid_folio nodes)
 *   pn->cache_ext_ds_registry : the lists
 *
 * This header reimplements those operations in BPF, replacing the kfuncs in
 * mm/cache_ext_ds.c. We start with the folio -> node lookup (read-only).
 *
 * Why bpf_probe_read_kernel instead of direct typed access: the lookup indexes
 * the bucket array valid_folios[bucket] with a *runtime* index, and the verifier
 * only allows constant offsets into a PTR_TO_BTF_ID. We therefore treat the
 * structures as raw kernel memory at known offsets. (Reads don't need the
 * MEM_WRITE exposure; that is for the write path, added later.)
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/*
 * Re-type a kernel address to a WRITABLE (MEM_WRITE) typed pointer (kfunc in
 * mm/cache_ext_ds.c, special-cased in the verifier). Unlike bpf_core_cast /
 * bpf_rdonly_cast (which yield untrusted read-only pointers), the result can be
 * stored into -- so a BPF policy can write the kernel-resident cache_ext data
 * structures it reached via a (read-only) lookup. addr is a scalar kernel
 * address; type is the struct type.
 */
extern void *bpf_cache_ext_writable_cast(__u64 addr, __u32 type_id) __ksym;
#define cache_ext_writable_cast(addr, type) \
	((type *)bpf_cache_ext_writable_cast((addr), bpf_core_type_id_kernel(type)))

/*
 * Convert a kernel pointer to a scalar u64. Casting a PTR_TO_BTF_ID to u64
 * keeps the verifier's pointer type, so arithmetic on it (the hash multiply,
 * base+index addressing) is rejected ("math between trusted_ptr pointer ... is
 * not allowed"); an empty-asm barrier does not break the type either. Spilling
 * the pointer to the stack and reading its bytes back with bpf_probe_read_kernel
 * does: the helper's output is unconditionally an unknown scalar.
 */
static __always_inline __u64 cache_ext_ptr_to_u64(const void *p)
{
	__u64 v = 0;
	const void *slot = p;

	bpf_probe_read_kernel(&v, sizeof(v), &slot);
	return v;
}

/* Mirror of the kernel hashtable parameters (include/linux/memcontrol.h,
 * include/linux/hash.h). Keep in sync with the kernel. */
#define CACHE_EXT_VFS_SIZE_POW   23                       /* VALID_FOLIOS_SET_SIZE_POW */
#define CACHE_EXT_GOLDEN_RATIO_64 0x61C8864680B583EBULL   /* GOLDEN_RATIO_64 */

/* Field offsets (bytes) in the kernel structs. Verified against vmlinux BTF.
 *   struct hlist_head  { struct hlist_node *first; }            first  @ 0
 *   struct hlist_node  { struct hlist_node *next, **pprev; }    next   @ 0
 *   struct valid_folio { hlist_node h_node; uintptr_t folio_ptr;
 *                        cache_ext_list_node *cache_ext_node; }
 *                        h_node @ 0, folio_ptr @ 16, cache_ext_node @ 24
 *   struct valid_folios_set { hlist_head valid_folios[1<<POW]; ... }
 *                        valid_folios @ 0  (element size 8)
 */
#define CACHE_EXT_OFF_VALID_FOLIO_FOLIO_PTR   16
#define CACHE_EXT_OFF_VALID_FOLIO_CACHE_NODE  24

#define CACHE_EXT_VFS_MAX_CHAIN  256   /* bound the hlist walk for the verifier */

/* hash_min(key, POW) for 64-bit keys == key * GOLDEN_RATIO_64 >> (64 - POW). */
static __always_inline __u64 cache_ext_vfs_bucket(__u64 folio_key)
{
	__u64 b = (folio_key * CACHE_EXT_GOLDEN_RATIO_64) >> (64 - CACHE_EXT_VFS_SIZE_POW);
	return b & ((1ULL << CACHE_EXT_VFS_SIZE_POW) - 1);
}

/*
 * BPF reimplementation of valid_folios_lookup(): given the writable parent node
 * and a folio, return the folio's cache_ext_list_node (or NULL). Read-only.
 */
static __always_inline struct cache_ext_list_node *
cache_ext_bpf_valid_folios_lookup(mem_cgroup_per_node_bpf_writable *pn,
				  struct folio *folio)
{
	struct valid_folios_set *vfs;
	__u64 key, vfs_addr, bucket, head_addr, node;
	int i;

	if (!pn)
		return NULL;
	vfs = pn->valid_folios_set;
	if (!vfs)
		return NULL;

	/* scalarize the folio pointer (the hash key) and the vfs base address. */
	key = cache_ext_ptr_to_u64(folio);
	vfs_addr = cache_ext_ptr_to_u64(vfs);

	bucket = cache_ext_vfs_bucket(key);
	/* &valid_folios[bucket] ; valid_folios is at offset 0, element size 8. */
	head_addr = vfs_addr + bucket * 8;

	/* node = valid_folios[bucket].first  (hlist_head.first @ 0) */
	node = 0;
	if (bpf_probe_read_kernel(&node, sizeof(node), (void *)head_addr))
		return NULL;

	for (i = 0; i < CACHE_EXT_VFS_MAX_CHAIN; i++) {
		__u64 folio_ptr = 0, cache_node = 0;

		if (!node)
			break;
		/* valid_folio->folio_ptr (h_node @0, folio_ptr @16) */
		if (bpf_probe_read_kernel(&folio_ptr, sizeof(folio_ptr),
					  (void *)(node + CACHE_EXT_OFF_VALID_FOLIO_FOLIO_PTR)))
			break;
		if (folio_ptr == key) {
			if (bpf_probe_read_kernel(&cache_node, sizeof(cache_node),
						  (void *)(node + CACHE_EXT_OFF_VALID_FOLIO_CACHE_NODE)))
				return NULL;
			return (struct cache_ext_list_node *)cache_node;
		}
		/* node = node->h_node.next  (hlist_node.next @ 0) */
		if (bpf_probe_read_kernel(&node, sizeof(node), (void *)node))
			break;
	}
	return NULL;
}

/*
 * BPF reimplementation of the list operations, writing the kernel-resident
 * list_head linkage directly through writable (MEM_WRITE) typed pointers.
 * `list` and `node` must be writable-cast pointers (cache_ext_writable_cast).
 *
 * Standard list_add_tail: insert `new` between head->prev and head.
 */
static __always_inline void
cache_ext_bpf_list_add_tail(struct cache_ext_list *list,
			    struct cache_ext_list_node *node)
{
	struct list_head *head = &list->head;
	struct list_head *new = &node->node;
	struct list_head *prev = head->prev;   /* MEM_WRITE via propagation */

	new->prev = prev;
	new->next = head;
	prev->next = new;
	head->prev = new;
}

/*
 * Standard list_del_init: unlink node from its list and re-init its links to
 * itself (so a subsequent add works and a double-del is harmless).
 */
static __always_inline void
cache_ext_bpf_list_del(struct cache_ext_list_node *node)
{
	struct list_head *n = &node->node;
	struct list_head *prev = n->prev;   /* MEM_WRITE via propagation */
	struct list_head *next = n->next;

	prev->next = next;
	next->prev = prev;
	n->next = n;
	n->prev = n;
}

/*
 * Iterate / count the list. Implemented with bpf_loop (a constant-bound for
 * loop is unrolled by clang -> -E2BIG) walking raw addresses with
 * bpf_probe_read_kernel (typed kernel pointers lose their BTF type when carried
 * through a bpf_loop callback ctx, and the walk is read-only so MEM_WRITE is
 * unneeded). list_head.next is at offset 0.
 */
#define CACHE_EXT_LIST_MAX_WALK (1u << 23)

struct cache_ext_walk_ctx {
	__u64 head;   /* &list->head */
	__u64 cur;    /* current list_head address */
	__u64 count;
};

static int cache_ext_list_walk_cb(__u32 i, void *vctx)
{
	struct cache_ext_walk_ctx *c = vctx;
	__u64 next = 0;

	if (c->cur == 0 || c->cur == c->head)
		return 1; /* stop */
	c->count++;
	if (bpf_probe_read_kernel(&next, sizeof(next), (void *)c->cur))
		return 1;
	c->cur = next;
	return 0;
}

static __always_inline __u64
cache_ext_bpf_list_count(struct cache_ext_list *list)
{
	struct cache_ext_walk_ctx c = {};
	__u64 first = 0;

	c.head = cache_ext_ptr_to_u64(&list->head);
	/* first = list->head.next */
	if (bpf_probe_read_kernel(&first, sizeof(first), (void *)c.head))
		return 0;
	c.cur = first;
	bpf_loop(CACHE_EXT_LIST_MAX_WALK, cache_ext_list_walk_cb, &c, 0);
	return c.count;
}

#endif /* _CACHE_EXT_DS_BPF_H */
