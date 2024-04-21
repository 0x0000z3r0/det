#include "def.h"
#include "z0_log.h"

#include <cpuid.h>

static usize
anti_vm_chk_cpuid(void)
{
	s32 res;

	u32 eax_in;
	u32 eax, ebx, ecx, edx;

	eax_in = 0x1;

	res = __get_cpuid(eax_in, &eax, &ebx, &ecx, &edx);
	if (res == -1) {
		log_err("failed to call CPUID, res: %i", res);
		return DET_STS_ERR;
	}

	if (ecx >> 31) {
		return DET_STS_FAILED;
	}

	return DET_STS_PASSED;
}

usize
det_anti_vm_init(struct det_ctx *ctx)
{
	log_inf("initializing the anti virtual machines module");

	usize sts;

	struct det_dsc dsc;

	dsc.name = "check CPUID";
	dsc.func = anti_vm_chk_cpuid;
	sts = vec_add(&ctx->vec_fns_anti_vm, &dsc);
	if (STS_ERR(sts))
		return sts;

	return DET_STS_OK;
}
