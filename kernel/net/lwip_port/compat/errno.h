/* errno.h shim for lwIP - use Kairos kernel errno values */
#ifndef _LWIP_COMPAT_ERRNO_H
#define _LWIP_COMPAT_ERRNO_H

#include <kairos/types.h>

/* lwIP may reference errno */
#ifndef errno
extern int errno;
#endif

#endif
