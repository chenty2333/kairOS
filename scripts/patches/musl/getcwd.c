#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include "syscall.h"

char *getcwd(char *buf, size_t size)
{
	char tmp[PATH_MAX];
	char *out = buf;

	if (!out) {
		out = tmp;
		size = sizeof(tmp);
	} else if (!size) {
		errno = EINVAL;
		return 0;
	}

	long ret = syscall(SYS_getcwd, out, size);
	if (ret < 0)
		return 0;
	if (ret == 0 || out[0] != '/') {
		errno = ENOENT;
		return 0;
	}

	return buf ? out : strdup(out);
}
