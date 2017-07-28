/* @LICENSE(MUSLC_MIT) */

#include <sys/resource.h>
#include <errno.h>
#include "internal/syscall.h"
#include "libc.h"

#define MIN(a, b) ((a)<(b) ? (a) : (b))

int __setrlimit(int resource, const struct rlimit *rlim)
{
	unsigned long k_rlim[2];
	int ret = __syscall(SYS_prlimit64, 0, resource, rlim, 0);
	if (ret != -ENOSYS) return ret;
	k_rlim[0] = MIN(rlim->rlim_cur, -1UL);
	k_rlim[1] = MIN(rlim->rlim_max, -1UL);
	return __syscall(SYS_setrlimit, resource, k_rlim);
}

struct ctx {
	const struct rlimit *rlim;
	int res;
	int err;
};

static void do_setrlimit(void *p)
{
	struct ctx *c = p;
	if (c->err) return;
	c->err = -__setrlimit(c->res, c->rlim);
}

int setrlimit(int resource, const struct rlimit *rlim)
{
	struct ctx c = { .res = resource, .rlim = rlim };
	__synccall(do_setrlimit, &c);
	if (c.err) {
		errno = c.err;
		return -1;
	}
	return 0;
}

LFS64(setrlimit);
