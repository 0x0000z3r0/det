#include "def.h"
#include "z0_log.h"
#include "z0_str.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

static usize __attribute__((noinline, section("fn_anti_dbg_chk_bp")))
anti_dbg_chk_bp(void)
{
	extern const u8 __start_fn_anti_dbg_chk_bp[];
	extern const u8 __stop_fn_anti_dbg_chk_bp[];

	usize len;
	len = __stop_fn_anti_dbg_chk_bp - __start_fn_anti_dbg_chk_bp;

	const u8 *cur = (u8*)anti_dbg_chk_bp;

	usize cnt;
	cnt = 0;
	for (usize i = 0; i < len; ++i) {
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

static usize __attribute__((noinline, section("fn_anti_dbg_chk_hash")))
anti_dbg_chk_hash(void)
{
	extern const u8 __start_fn_anti_dbg_chk_hash[];
	extern const u8 __stop_fn_anti_dbg_chk_hash[];

	usize len;
	len = __stop_fn_anti_dbg_chk_hash - __start_fn_anti_dbg_chk_hash;

	const u8 *cur = (u8*)anti_dbg_chk_hash;

	usize hash_old;
	usize hash_new;

	hash_old = 0;
	hash_new = 0;

	for (usize i = 0; i < len; ++i) {
		hash_old += __start_fn_anti_dbg_chk_hash[i];
		hash_new += cur[i];
	}

	if (hash_old != hash_new) {
		return DET_STS_FAILED;
	}

	return DET_STS_PASSED;
}

static usize
anti_dbg_chk_trc_id(void)
{
	s32 file;
	file = open("/proc/self/status", O_RDONLY);
	if (file == -1) {
		log_err("failed to open, err: %s", strerror(errno));
		return DET_STS_FAILED;
	}

	usize sts;
	sts = DET_STS_PASSED;

	struct str str_status;
	sts = str_new_cap(&str_status, 1024);
	if (STS_ERR(sts)) {
		log_err("failed to create a new string, sts: %zu", sts);
		goto _CLOSE;
	}

	ssize_t bytes;
	bytes = 0;

	s8 buf[512];
	do {
		bytes = read(file, buf, sizeof (buf));
		if (bytes == -1) {
			log_err("failed to read, err: %s", strerror(errno));
			sts = DET_STS_ERR;

			goto _STR_DEL;
		}

		sts = str_cat(&str_status, bytes, buf);
		if (STS_ERR(sts)) {
			log_err("failed to concatenate, sts: %zu", sts);
			sts = DET_STS_ERR;

			goto _STR_DEL;
		}

	} while (bytes != 0);

	pid_t pid;
	static const s8 trc_id[] = "TracerPid:";

	usize start;
	sts = str_pos(&str_status, &start, sizeof (trc_id) - 1, trc_id);
	if (STS_OK(sts)) {
		start += sizeof (trc_id) - 1;

		for (usize i = start; i < str_status.len; ++i) {
			if (str_status.ptr[i] == ' ' || str_status.ptr[i] == '\t')
				continue;

			usize end;
			sts = str_pos_off(&str_status, &end, i, 1, (const s8*)"\n");
			if (STS_OK(sts)) {
				struct str_ref ref;
				str_ref(&ref, end - i, str_status.ptr + i);

				str_ref_s32(&ref, &pid);

				log_dbg("tracer pid: %i", pid);
				break;
			}
		}
	}

	if (pid != 0) {
		return DET_STS_FAILED;
	}

_STR_DEL:
	str_del(&str_status);
_CLOSE:
	close(file);
	return DET_STS_PASSED;
}

static usize
anti_dbg_chk_ptrace(void)
{
	s32 sts;

	pid_t pid;
	pid = vfork();
	if (pid == -1) {
		log_err("failed to fork, err: %s", strerror(errno));
		return DET_STS_ERR;
	}

	if (pid == 0) {
		pid_t ppid;
		ppid = getppid();

		s32 res;
		res = ptrace(PTRACE_ATTACH, ppid, NULL, NULL);
		if (res == -1) {
			exit(DET_STS_FAILED);
		}

		res = waitpid(ppid, NULL, 0);
		if (res == -1) {
			log_err("failed to wait for the parent, err: %s", strerror(errno));
			exit(DET_STS_ERR);
		}

		res = ptrace(PTRACE_CONT, ppid, NULL, NULL);
		if (res == -1) {
			log_err("failed to continue the parent, err: %s", strerror(errno));
			exit(DET_STS_ERR);
		}

		res = ptrace(PTRACE_DETACH, ppid, NULL, NULL);
		if (res == -1) {
			log_err("failed to detach the parent, err: %s", strerror(errno));
			exit(DET_STS_ERR);
		}

		exit(DET_STS_PASSED);
	} else {
		s32 res;

		res = waitpid(pid, &sts, 0);
		if (res == -1) {
			log_err("failed to wait for the child, err: %s", strerror(errno));
			return DET_STS_ERR;
		}

		sts = WEXITSTATUS(sts);
	}

	if (sts == 1) {
		return DET_STS_FAILED;
	}

	return DET_STS_PASSED;
}

usize
det_anti_dbg_init(struct det_ctx *ctx)
{
	log_inf("initializing the anti-debugging module");

	usize sts;

	struct det_dsc dsc;

	dsc.name = "check breakpoint";
	dsc.func = anti_dbg_chk_bp;
	sts = vec_add(&ctx->vec_fns_anti_dbg, &dsc);
	if (STS_ERR(sts))
		return sts;

	dsc.name = "check hash";
	dsc.func = anti_dbg_chk_hash;
	sts = vec_add(&ctx->vec_fns_anti_dbg, &dsc);
	if (STS_ERR(sts))
		return sts;

	dsc.name = "check tracer id";
	dsc.func = anti_dbg_chk_trc_id;
	sts = vec_add(&ctx->vec_fns_anti_dbg, &dsc);
	if (STS_ERR(sts))
		return sts;

	dsc.name = "check ptrace";
	dsc.func = anti_dbg_chk_ptrace;
	sts = vec_add(&ctx->vec_fns_anti_dbg, &dsc);
	if (STS_ERR(sts))
		return sts;

	return DET_STS_OK;
}
