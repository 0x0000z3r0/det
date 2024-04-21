#include "def.h"
#include "z0_log.h"

static uint
det_vec_iter(struct vec *vec)
{
	uint sts;

	static const char *col[] = { COL_GRN, COL_RED };
	static const char *res[] = { "PASSED", "FAILED" };

	log_inf("found %zu functions", vec->len);
	for (uint i = 0; i < vec->len; ++i) {
		struct det_dsc dsc;
		sts = vec_get(vec, i, &dsc);
		if (STS_ERR(sts)) {
			log_err("failed to get the function at index: %zu, sts: %zu\n", i, sts);
			return DET_STS_ERR;
		}

		sts = dsc.func();
		if (STS_ERR(sts)) {
			log_err("failed to run the function at index: %zu, sts: %zu\n", i, sts);
			return DET_STS_ERR;
		}

		uint ret;
		ret = sts == DET_STS_FAILED;
		log_inf("called " COL_MAG "[%s]" COL_NRM ", status: %s%s" COL_NRM, dsc.name, col[ret], res[ret]);
	}
			
	return DET_STS_OK;
}

s32
main(void)
{
	log_lvl(LOG_LVL_DBG);
	log_inf("initializing modules");

	struct det_ctx ctx;

	uint sts;
	sts = vec_new(&ctx.vec_fns_anti_dbg, sizeof (struct det_dsc));
	if (STS_ERR(sts)) {
		log_err("failed to create module vector, sts: %zu\n", sts);
		return 0;
	}

	sts = vec_new(&ctx.vec_fns_anti_vm, sizeof (struct det_dsc));
	if (STS_ERR(sts)) {
		log_err("failed to create module vector, sts: %zu\n", sts);
		return 0;
	}

	sts = det_anti_dbg_init(&ctx);
	if (STS_ERR(sts)) {
		log_err("failed to initialize the anti-debugging module, sts: %zu\n", sts);
		goto _EXIT;
	}

	sts = det_anti_vm_init(&ctx);
	if (STS_ERR(sts)) {
		log_err("failed to initialize the anti-virtual machines module, sts: %zu\n", sts);
		goto _EXIT;
	}

	sts = det_vec_iter(&ctx.vec_fns_anti_dbg);
	if (STS_ERR(sts)) {
		log_err("failed to iterate over the anti-debugging module, sts: %zu\n", sts);
		goto _EXIT;
	}

	sts = det_vec_iter(&ctx.vec_fns_anti_vm);
	if (STS_ERR(sts)) {
		log_err("failed to iterate over the anti-virtual machines module, sts: %zu\n", sts);
		goto _EXIT;
	}

_EXIT:
	vec_del(&ctx.vec_fns_anti_vm);
	vec_del(&ctx.vec_fns_anti_dbg);
	return 0;
}
