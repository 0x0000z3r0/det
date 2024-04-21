#ifndef _DEF_H_
#define _DEF_H_

#define Z0_USE_NAMESPACE
#include "z0_vec.h"

#define DET_STS_OK	STS_NEW(0, STS_LVL_INF)
#define DET_STS_PASSED	STS_NEW(1, STS_LVL_INF)
#define DET_STS_FAILED	STS_NEW(2, STS_LVL_INF)
#define DET_STS_ERR	STS_NEW(0, STS_LVL_ERR)

typedef usize (*det_fn)(void);

struct det_dsc {
	const char *name;
	det_fn func;
};

struct det_ctx {
	struct vec vec_fns_anti_dbg;
	struct vec vec_fns_anti_vm;
};

usize
det_anti_dbg_init(struct det_ctx*);

usize
det_anti_vm_init(struct det_ctx*);

#endif
