#include "def.h"
#include "z0_log.h"

static uint __attribute__((noinline, section("fn_anti_dbg_chk_bp")))
anti_dbg_chk_bp(void)
{
	extern const u8 __start_fn_anti_dbg_chk_bp[];
	extern const u8 __stop_fn_anti_dbg_chk_bp[];

	uint len;
	len = __stop_fn_anti_dbg_chk_bp - __start_fn_anti_dbg_chk_bp;

	const u8 *cur = (u8*)anti_dbg_chk_bp;

	uint cnt;
	cnt = 0;
	for (uint i = 0; i < len; ++i) {
		if (cur[i] == 0xCC) {
			log_dbg("found INT3 instruction at offset: %zu, function size: %zu", i, len);
			++cnt;
		}
		
		if (cnt > 1) {
			return DET_STS_FAILED;
		}
	}

	return DET_STS_PASSED;
}

static uint __attribute__((noinline, section("fn_anti_dbg_chk_hash")))
anti_dbg_chk_hash(void)
{
	extern const u8 __start_fn_anti_dbg_chk_hash[];
	extern const u8 __stop_fn_anti_dbg_chk_hash[];

	uint len;
	len = __stop_fn_anti_dbg_chk_hash - __start_fn_anti_dbg_chk_hash;

	const u8 *cur = (u8*)anti_dbg_chk_hash;

	uint hash_old;
	uint hash_new;

	hash_old = 0;
	hash_new = 0;

	for (uint i = 0; i < len; ++i) {
		hash_old += __start_fn_anti_dbg_chk_hash[i];
		hash_new += cur[i];
	}

	if (hash_old != hash_new) {
		return DET_STS_FAILED;
	}

	return DET_STS_PASSED;
}

uint
det_anti_dbg_init(struct det_ctx *ctx)
{
	log_inf("initializing the anti-debugging module");

	uint sts;

	struct det_dsc dsc;

	dsc.name = "Check breakpoint";
	dsc.func = anti_dbg_chk_bp;
	sts = vec_add(&ctx->vec_fns_anti_dbg, &dsc);
	if (STS_ERR(sts))
		return sts;

	dsc.name = "Check hash";
	dsc.func = anti_dbg_chk_hash;
	sts = vec_add(&ctx->vec_fns_anti_dbg, &dsc);
	if (STS_ERR(sts))
		return sts;

	return DET_STS_OK;
}
