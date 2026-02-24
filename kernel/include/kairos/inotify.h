#ifndef _KAIROS_INOTIFY_H
#define _KAIROS_INOTIFY_H

#include <kairos/vfs.h>

#define IN_ACCESS 0x00000001U
#define IN_MODIFY 0x00000002U
#define IN_ATTRIB 0x00000004U
#define IN_CLOSE_WRITE 0x00000008U
#define IN_CLOSE_NOWRITE 0x00000010U
#define IN_OPEN 0x00000020U
#define IN_MOVED_FROM 0x00000040U
#define IN_MOVED_TO 0x00000080U
#define IN_CREATE 0x00000100U
#define IN_DELETE 0x00000200U
#define IN_DELETE_SELF 0x00000400U
#define IN_MOVE_SELF 0x00000800U
#define IN_UNMOUNT 0x00002000U
#define IN_Q_OVERFLOW 0x00004000U
#define IN_IGNORED 0x00008000U

#define IN_ONLYDIR 0x01000000U
#define IN_DONT_FOLLOW 0x02000000U
#define IN_EXCL_UNLINK 0x04000000U
#define IN_MASK_CREATE 0x10000000U
#define IN_MASK_ADD 0x20000000U
#define IN_ISDIR 0x40000000U
#define IN_ONESHOT 0x80000000U

#define IN_ALL_EVENTS (IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | \
                       IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | \
                       IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_DELETE_SELF | \
                       IN_MOVE_SELF)

#define IN_CLOEXEC O_CLOEXEC
#define IN_NONBLOCK O_NONBLOCK

void inotify_fsnotify(struct vnode *vn, const char *name, uint32_t mask,
                      uint32_t cookie);
uint32_t inotify_next_cookie(void);

#endif
