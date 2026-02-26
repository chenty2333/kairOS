#ifndef KAIROS_PIDFD_H
#define KAIROS_PIDFD_H

#include <kairos/types.h>

struct file;

int pidfd_get_pid(struct file *file, pid_t *pid_out);

#endif
