#pragma once

#include "bpf_arena.h"

#ifndef div_round_up
#define div_round_up(a, b) (((a) + (b) - 1) / (b))
#endif

enum sdt_task_consts {
	SDT_TASK_LEVELS			= 3,
	SDT_TASK_ENT_SIZE		= sizeof(void *),
	SDT_TASK_ENTS_PER_CHUNK_SHIFT	= 9,
	SDT_TASK_ENTS_PER_CHUNK		= 1 << SDT_TASK_ENTS_PER_CHUNK_SHIFT,
	SDT_TASK_CHUNK_BITMAP_U64S	= div_round_up(SDT_TASK_ENTS_PER_CHUNK, 64),
};

union sdt_task_id {
	__s64				val;
	struct {
		__s32			idx;
		__s32			gen;
	};
};

struct sdt_task_chunk;

struct sdt_task_desc {
	__u64				bitmap[SDT_TASK_CHUNK_BITMAP_U64S];
	__u64				nr_free;
	struct sdt_task_chunk __arena	*chunk;
};

struct sdt_task_data {
	union sdt_task_id		tid;
	__u64				tptr;
	__u64				data[];
};

struct sdt_task_chunk {
	union {
		struct sdt_task_desc __arena *descs[SDT_TASK_ENTS_PER_CHUNK];
		struct sdt_task_data __arena *data[SDT_TASK_ENTS_PER_CHUNK];
	};
};
