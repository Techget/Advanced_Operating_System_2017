/* @LICENSE(MUSLC_MIT) */

#include "pthread_impl.h"

int pthread_barrierattr_setpshared(pthread_barrierattr_t *a, int pshared)
{
	*a = pshared ? INT_MIN : 0;
	return 0;
}
