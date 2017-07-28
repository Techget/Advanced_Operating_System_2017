/* @LICENSE(MUSLC_MIT) */

#include <signal.h>
#include <errno.h>
#include "internal/syscall.h"

int sigaltstack(const stack_t *ss, stack_t *old)
{
	if (ss) {
		if (ss->ss_size < MINSIGSTKSZ) {
			errno = ENOMEM;
			return -1;
		}
		if (ss->ss_flags & ~SS_DISABLE) {
			errno = EINVAL;
			return -1;
		}
	}
	return syscall(SYS_sigaltstack, ss, old);
}
