#pragma once

#include "sdt_task.h"

#define SDT_TASK_FN_ATTRS	inline __attribute__((unused, always_inline))

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1 << 20); /* number of pages */
#ifdef __TARGET_ARCH_arm64
        __ulong(map_extra, (1ull << 32) | (~0u - __PAGE_SIZE * 2 + 1)); /* start of mmap() region */
#else
        __ulong(map_extra, (1ull << 44) | (~0u - __PAGE_SIZE * 2 + 1)); /* start of mmap() region */
#endif
} arena __weak SEC(".maps");

struct sdt_task_map_val {
	union sdt_task_id		tid;
	struct sdt_task_data __arena	*data;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sdt_task_map_val);
} sdt_task_map SEC(".maps");

struct sdt_task_desc_root __arena *sdt_task_desc_root;
struct sdt_task_desc __arena *sdt_task_new_chunk;

private(LOCK) struct bpf_spin_lock sdt_task_lock;
private(POOL_LOCK) struct bpf_spin_lock sdt_task_pool_alloc_lock;

struct sdt_task_pool_elem {
	struct sdt_task_pool_elem __arena *next;
};

struct sdt_task_pool {
	struct sdt_task_pool_elem __arena *first;
	__u64				elem_size;
};

struct sdt_task_pool __arena_global sdt_task_desc_pool = {
	.elem_size			= sizeof(sdt_task_desc),
};

struct sdt_task_pool __arena_global sdt_task_chunk_pool = {
	.elem_size			= sizeof(sdt_task_chunk),
};

struct sdt_task_pool __arena_global sdt_task_data_pool;

static SDT_TASK_FN_ATTRS int sdt_ffs(__u64 word)
{
	unsigned int num = 0;

	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

static SDT_TASK_FN_ATTRS __s64 sdt_task_find_empty(struct sdt_task_desc __arena *desc)
{
	__u64 pos = 0;
	__u64 i;

	for (i = 0; i < SDT_TASK_CHUNK_BITMAP_U64S; i++) {
		if (desc->bitmap[i] == ~(__u64)0)
			pos += 64;
		else
			return pos + sdt_ffs(~desc->bitmap[i]);
	}

	return -EBUSY;
}

static SDT_TASK_FN_ATTRS
void __arena *sdt_task_alloc_from_pool(struct sdt_task_pool __arena *pool)
{
	struct sdt_task_pool_elem __arena *elem = NULL;
	void __arena *new_page = NULL;
	__u32 u;

	bpf_repeat(2) {
		if (!pool->first) {
			new_page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
			if (!new_page)
				return NULL;
		}

		bpf_spin_lock(&sdt_task_pool_alloc_lock);

		if (!pool->first && new_page) {
			bpf_for(u, 0, PAGE_SIZE / pool->elem_size) {
				struct sdt_task_pool_elem __arena *new_elem =
					new_page + u * pool->elem_size;

				new_elem->next = pool->first;
				pool->first = new_elem;
			}
			new_page = NULL;
		}

		if (pool->first) {
			elem = pool->first;
			pool->first = elem->next;
			bpf_spin_unlock(&sdt_task_pool_alloc_lock);
			break;
		}

		bpf_spin_unlock(&sdt_task_pool_alloc_lock);
	}

	if (new_page)
		bpf_arena_free_pages(&arena, new_page, 1);

	return (void __arena *)elem;
}

static SDT_TASK_FN_ATTRS
void sdt_task_free_to_pool(void __arena *ptr, struct sdt_task_pool __arena *pool)
{
	struct sdt_task_pool_elem __arena *elem = ptr;

	bpf_spin_lock(&sdt_task_pool_alloc_lock);
	elem->next = pool->first;
	pool->first = elem;
	bpf_spin_unlock(&sdt_task_pool_alloc_lock);
}

static SDT_TASK_FN_ATTRS struct sdt_task_desc __arena *sdt_alloc_chunk(void)
{
	struct sdt_task_chunk __arena *chunk;
	struct sdt_task_desc __arena *desc;

	chunk = sdt_task_alloc_from_pool(&sdt_task_chunk_pool);
	if (!chunk)
		return NULL;
	desc = sdt_task_alloc_from_pool(&sdt_task_desc_pool);
	if (!desc) {
		sdt_task_free_to_pool(&sdt_task_chunk_pool, chunk);
		return NULL;
	}

	desc->nr_free = SDT_TASK_ENTS_PER_CHUNK;
	desc->chunk = chunk;
	return desc;
}

static SDT_TASK_FN_ATTRS void sdt_free_chunk(struct sdt_task_desc __arena *desc)
{
	memset(desc->chunk, 0, sizeof(*desc->chunk));
	sdt_task_free_to_pool(desc->chunk, &sdt_task_chunk_pool);
	memset(desc, 0, sizeof(*desc));
	sdt_task_free_to_pool(desc, &dst_task_desc_pool);
}

static SDT_TASK_FN_ATTRS int sdt_task_init(__u64 data_size)
{
	data_size = div_round_up(data_size, 8) * 8;
	data_size += sizeof(struct sdt_task_data);

	if (data_size > PAGE_SIZE)
		return -E2BIG;

	sdt_task_data_pool.elem_size = data_size;

	sdt_task_desc_root = sdt_alloc_chunk();
	if (!sdt_task_desc_root)
		return -ENOMEM;

	return 0;
}

static SDT_TASK_FN_ATTRS void sdt_task_free_idx(int idx)
{
	struct sdt_task_desc __arena *desc = sdt_task_desc_root;
	struct sdt_task_data __arena *data;
	__u64 level, pos;

	bpf_spin_lock(&sdt_task_lock);

	bpf_for(level, 0, SDT_TASK_LEVELS) {
		pos = ((__u64)idx >> ((SDT_TASK_LEVELS - 1 - level) *
				      SDT_TASK_ENTS_PER_CHUNK_SHIFT)) &
			((1 << SDT_TASK_ENTS_PER_CHUNK_SHIFT) - 1);

		desc->bitmap[pos / 64] &= ~(1LU << (pos & 0x3f));
		desc->nr_free++;

		desc = desc->chunk->descs[pos];
	}

	data = (void __arena *)desc;
	if (data) {
		data->tid.gen++;
		data->tptr = NULL;
		memset(data->data, 0, sdt_task_data_pool.elem_size -
		       offsetof(struct sdt_task_data, data));
	}

	bpf_spin_unlock(&sdt_task_lock);
}

static SDT_TASK_FN_ATTRS void sdt_task_free(struct task_struct *p)
{
	struct std_task_map_val *mval;

	mval = bpf_task_storage_get(&sdt_task_map, p, 0, 0);
	if (!mval)
		return;

	sdt_task_free_idx(mval->tid.idx);
	mval->data = NULL;
}

static SDT_TASK_FN_ATTRS struct sdt_task_data __arena *sdt_task_alloc(struct task_struct *p)
{
	struct sdt_task_desc __arena *new_chunk = NULL;
	struct sdt_task_data __arena *data = NULL;
	struct sdt_task_map_val *mval;

	mval = bpf_task_storage_get(&sdt_task_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!mval)
		return NULL;

	bpf_spin_lock(&sdt_task_lock);

	bpf_repeat(8192) {
		struct sdt_task_desc __arena *desc = sdt_task_desc_root;
		void __arena *level_desc[SDT_TASK_LEVELS];
		__u64 level_pos[SDT_TASK_LEVELS];
		__u64 u, level;
		__s64 idx = 0, pos = 0;

		bpf_for(level, 0, SDT_TASK_LEVELS - 1) {
			pos = sdt_task_find_empty(desc);
			if (pos < 0)
				goto out_unlock;

			level_desc[level] = desc;
			level_pos[level] = pos;
			idx |= pos << ((SDT_TASK_LEVELS - 1 - level) *
				       SDT_TASK_ENTS_PER_CHUNK_SHIFT);

			desc = desc->chunk->descs[pos];
			if (!desc) {
				if (!new_chunk && sdt_task_new_chunk) {
					new_chunk = sdt_task_new_chunk;
					sdt_task_new_chunk = NULL;
				}

				if (new_chunk) {
					desc->chunk->descs[pos] = new_chunk;
					desc = new_chunk;
					new_chunk = NULL;
				} else {
					bpf_spin_unlock(&sdt_task_lock);
					new_chunk = sdt_alloc_chunk();
					if (!new_chunk)
						return NULL;
					bpf_spin_lock(&sdt_task_lock);
					goto retry;
				}
			}
		}
		break;
	retry:
	}

	pos = sdt_task_find_empty(desc);
	if (pos < 0)
		goto out_unlock;

	level_desc[level] = desc;
	level_desc[level] = pos;
	idx |= pos;

	bpf_for(u, 0, SDT_TASK_LEVELS) {
		__u64 lv = SDT_TASK_LEVELS - 1 - u;
		struct sdt_task_desc __arena *lv_desc = level_descs[lv];
		__u64 lv_pos = level_pos[lv];

		lv_desc->bitmap[lv_pos / 64] |= 1LU << (lv_pos & 0x3f);
		if (--lv_desc->nr_free)
			goto out_unlock;
	}

	data = desc->chunk->data[pos];
	if (!data) {
		bpf_spin_unlock(&sdt_task_lock);
		data = sdt_alloc_from_pool(&sdt_task_data_pool);
		if (!data)
			sdt_task_free_idx(idx);
		bpf_spin_lock(&sdt_task_lock);
		if (!data)
			goto out_unlock;

		data->tid.idx = idx;
		desc->chunk->data[pos] = data;
	}

	data->tptr = (__u64)p;
	mval->tid = data->tid;
	mval->data = data;

out_unlock:
	if (new_chunk && !sdt_task_new_chunk) {
		sdt_task_new_chunk = new_chunk;
		new_chunk = NULL;
	}
	bpf_spin_unlock(&sdt_task_lock);
	if (new_chunk)
		sdt_task_free_chunk(new_chunk);
	return data;
}
