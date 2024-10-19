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

struct sdt_task_desc_root __arena *sdt_task_desc_root;

private(ALLOC_BUF) struct bpf_spin_lock sdt_task_buf_alloc_lock;

struct sdt_alloc_buf_elem {
	struct sdt_alloc_buf_elem __arena *next;
};

struct sdt_alloc_buf {
	struct sdt_alloc_buf_elem __arena *first;
	__u64				elem_size;
};

struct sdt_alloc_buf __arena_global sdt_task_desc_buf = {
	.elem_size			= sizeof(sdt_task_desc),
};

struct sdt_alloc_buf __arena_global sdt_task_chunk_buf = {
	.elem_size			= sizeof(sdt_task_chunk),
};

struct sdt_alloc_buf __arena_global sdt_task_data_buf;

static SDT_TASK_FN_ATTRS int sdt_ffz(__u64 word)
{
	unsigned int num = 0;

	if ((word & 0xffffffff) == 0xffffffff) {
		num += 32;
		word >>= 32;
	}
	if ((word & 0xffff) == 0xffff) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0xff) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0xf) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0x3) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0x1)
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
			return pos + sdt_ffz(desc->bitmap[i]);
	}

	return -EBUSY;
}

static SDT_TASK_FN_ATTRS
void __arena *sdt_task_alloc_from_buf(struct sdt_alloc_buf __arena *buf)
{
	struct sdt_alloc_buf_elem __arena *elem = NULL;
	void __arena *new_page = NULL;
	__u32 u;

	bpf_repeat(2) {
		if (!buf->first) {
			new_page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
			if (!new_page)
				return NULL;
		}

		bpf_spin_lock(&sdt_task_buf_alloc_lock);

		if (!buf->first && new_page) {
			bpf_for(u, 0, PAGE_SIZE / buf->elem_size) {
				struct sdt_alloc_buf_elem __arena *new_elem =
					new_page + u * buf->elem_size;

				new_elem->next = buf->first;
				buf->first = new_elem;
			}
			new_page = NULL;
		}

		if (buf->first) {
			elem = buf->first;
			buf->first = elem->next;
			bpf_spin_unlock(&sdt_tasnk_buf_alloc_lock);
			break;
		}

		bpf_spin_unlock(&sdt_task_buf_alloc_lock);
	}

	if (new_page)
		bpf_arena_free_pages(&arena, new_page, 1);
	return (void __arena *)elem;
}

static SDT_TASK_FN_ATTRS
void sdt_task_free_to_buf(void __arena *ptr, struct sdt_alloc_buf __arena *buf)
{
	struct sdt_alloc_buf_elem __arena *elem = ptr;

	bpf_spin_lock(&sdt_task_buf_alloc_lock);
	elem->next = buf->first;
	buf->first = elem;
	bpf_spin_unlock(&sdt_task_buf_alloc_lock);
}

static SDT_TASK_FN_ATTRS int sdt_task_init(__u64 data_size)
{
	data_size += sizeof(struct sdt_task_data);

	if (data_size > PAGE_SIZE)
		return -E2BIG;

	sdt_task_data_buf.elem_size = data_size;

	sdt_task_desc_root = sdt_alloc_from_buf(&sdt_task_desc_buf);
	if (!sdt_task_desc_root)
		return -ENOMEM;

	return 0;
}

static SDT_TASK_FN_ATTRS struct sdt_task_data __arena *sdt_task_alloc(struct task_struct *p)
{
	void __arena *ptr = sdt_task_desc_root;
	__u64 level;
	__s64 idx = 0, pos = 0;

	bpf_for(level, 0, SDT_TASK_LEVELS) {
		struct sdt_task_desc __arena *desc = ptr;

		pos = sdt_task_find_empty(desc);
		if (pos < 0)
			return NULL;

		idx <<= SDT_TASK_ENTS_PER_CHUNK_SHIFT;
		idx += pos;

		if (level < 2) {
			if (!desc->chunk->descs[pos]) {
				desc->chunk->descs[pos] =
					sdt_alloc_from_buf(&sdt_task_chunk_buf);
				if (!desc->chunk->descs[pos])
					return NULL;
			}
		}
	}
}

