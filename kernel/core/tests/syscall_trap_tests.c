/**
 * kernel/core/tests/syscall_trap_tests.c - Syscall/trap boundary tests
 */

#include <kairos/arch.h>
#include <kairos/fault_inject.h>
#include <kairos/futex.h>
#include <kairos/handle.h>
#include <kairos/ioctl.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/time.h>
#include <kairos/trap_core.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#if CONFIG_KERNEL_TESTS

#ifndef CONFIG_SYSCALL_TRAP_IPC_CAP_ONLY
#define CONFIG_SYSCALL_TRAP_IPC_CAP_ONLY 0
#endif

static int tests_failed;

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("syscall_trap_tests: %s failed\n", name);
        tests_failed++;
    }
}

static int trap_handle_calls;
static int trap_should_deliver_calls;
static bool trap_handler_saw_current_tf;
static bool trap_handler_saw_process_tf;
static struct trap_frame *trap_handler_tf;

#define TEST_NS_PER_SEC 1000000000ULL
#define SYSCALL_USER_TEST_CODE_ADDR 0x12000

struct user_map_ctx {
    struct process *proc;
    struct mm_struct *saved_mm;
    struct mm_struct *active_mm;
    struct mm_struct *temp_mm;
    paddr_t saved_pgdir;
    vaddr_t base;
    size_t len;
    bool switched_pgdir;
};

struct futex_waker_ctx {
    vaddr_t uaddr;
    volatile int started;
    int wake_ret;
};

#define KH_STRESS_PRODUCERS 4U
#define KH_STRESS_CONSUMERS 3U
#define KH_STRESS_MSGS_PER_PRODUCER 48U
#define KH_STRESS_TOTAL_MSGS \
    (KH_STRESS_PRODUCERS * KH_STRESS_MSGS_PER_PRODUCER)
#define KH_STRESS_RUN_TIMEOUT_NS (20ULL * TEST_NS_PER_SEC)
#define KH_STRESS_WAIT_SLICE_NS (50ULL * 1000ULL * 1000ULL)
#define KH_STRESS_ACK_TIMEOUT_NS (2ULL * TEST_NS_PER_SEC)
#define KH_STRESS_TAG 0x4B485354U

struct kh_stress_msg {
    uint32_t producer_id;
    uint32_t seq;
    uint32_t tag;
};

struct kh_stress_ack {
    uint32_t producer_id;
    uint32_t seq;
};

struct kh_stress_suite {
    atomic_t sent;
    atomic_t received;
    atomic_t acked;
    atomic_t producers_done;
    atomic_t errors;
};

struct kh_stress_producer_ctx {
    struct kh_stress_suite *suite;
    int32_t h_send;
    int32_t h_ack_send;
    int32_t h_ack_recv;
    uint32_t producer_id;
};

struct kh_stress_consumer_ctx {
    struct kh_stress_suite *suite;
    int32_t h_recv;
    int32_t h_port;
};

struct kh_rendezvous_ctx {
    struct kobj *recv_obj;
    volatile int armed;
    int rc;
    size_t got_bytes;
    size_t got_handles;
    bool trunc;
    char payload[8];
};

static int user_map_begin(struct user_map_ctx *ctx, size_t len) {
    if (!ctx || len == 0)
        return -EINVAL;

    memset(ctx, 0, sizeof(*ctx));
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    ctx->proc = p;
    ctx->saved_mm = p->mm;
    ctx->active_mm = p->mm;
    ctx->saved_pgdir = arch_mmu_current();

    if (!ctx->active_mm) {
        ctx->temp_mm = mm_create();
        if (!ctx->temp_mm)
            return -ENOMEM;
        p->mm = ctx->temp_mm;
        ctx->active_mm = ctx->temp_mm;
    }

    if (ctx->saved_pgdir != ctx->active_mm->pgdir) {
        arch_mmu_switch(ctx->active_mm->pgdir);
        ctx->switched_pgdir = true;
    }

    int rc = mm_mmap(ctx->active_mm, 0, len, VM_READ | VM_WRITE, 0, NULL, 0,
                     false, &ctx->base);
    if (rc < 0) {
        if (ctx->switched_pgdir)
            arch_mmu_switch(ctx->saved_pgdir);
        if (ctx->temp_mm) {
            p->mm = ctx->saved_mm;
            mm_destroy(ctx->temp_mm);
        }
        memset(ctx, 0, sizeof(*ctx));
        return rc;
    }
    ctx->len = len;
    return 0;
}

static void user_map_end(struct user_map_ctx *ctx) {
    if (!ctx || !ctx->proc)
        return;
    if (ctx->active_mm && ctx->base && ctx->len)
        (void)mm_munmap(ctx->active_mm, ctx->base, ctx->len);
    if (ctx->switched_pgdir)
        arch_mmu_switch(ctx->saved_pgdir);
    if (ctx->temp_mm) {
        ctx->proc->mm = ctx->saved_mm;
        mm_destroy(ctx->temp_mm);
    }
    memset(ctx, 0, sizeof(*ctx));
}

static void *user_map_ptr(const struct user_map_ctx *ctx, size_t off) {
    if (!ctx || off >= ctx->len)
        return NULL;
    return (void *)(ctx->base + off);
}

static struct timespec ns_to_timespec(uint64_t ns) {
    struct timespec ts = {
        .tv_sec = (time_t)(ns / TEST_NS_PER_SEC),
        .tv_nsec = (int64_t)(ns % TEST_NS_PER_SEC),
    };
    return ts;
}

static int futex_waitv_waker_worker(void *arg) {
    struct futex_waker_ctx *ctx = (struct futex_waker_ctx *)arg;
    if (!ctx)
        proc_exit(0);

    ctx->started = 1;
    ctx->wake_ret = 0;
    uint64_t wake_deadline = arch_timer_get_ticks() +
                             arch_timer_ns_to_ticks(2ULL * TEST_NS_PER_SEC);
    if (wake_deadline == 0)
        wake_deadline = 1;
    while (arch_timer_get_ticks() < wake_deadline) {
        int64_t ret = sys_futex((uint64_t)ctx->uaddr, FUTEX_WAKE, 1, 0, 0, 0);
        if (ret > 0) {
            ctx->wake_ret = (int)ret;
            proc_exit(0);
        }
        proc_yield();
    }
    proc_exit(0);
}

static int kh_rendezvous_recv_worker(void *arg) {
    struct kh_rendezvous_ctx *ctx = (struct kh_rendezvous_ctx *)arg;
    if (!ctx || !ctx->recv_obj)
        proc_exit(1);

    ctx->armed = 1;
    size_t got_bytes = 0;
    size_t got_handles = 0;
    bool trunc = false;
    ctx->rc = kchannel_recv(ctx->recv_obj, ctx->payload, sizeof(ctx->payload),
                            &got_bytes, NULL, 0, &got_handles, &trunc,
                            KCHANNEL_OPT_RENDEZVOUS);
    ctx->got_bytes = got_bytes;
    ctx->got_handles = got_handles;
    ctx->trunc = trunc;
    proc_exit(0);
}

static void kh_stress_mark_error(struct kh_stress_suite *suite) {
    if (suite)
        atomic_inc(&suite->errors);
}

static bool kh_wait_pid_bounded(pid_t pid, uint64_t timeout_ns) {
    int status = 0;
    uint64_t deadline = time_now_ns() + timeout_ns;
    while (time_now_ns() < deadline) {
        pid_t got = proc_wait(pid, &status, WNOHANG);
        if (got == pid)
            return true;
        if (got < 0)
            return false;
        proc_yield();
    }
    return proc_wait(pid, &status, WNOHANG) == pid;
}

static int kh_stress_producer_worker(void *arg) {
    struct kh_stress_producer_ctx *ctx = (struct kh_stress_producer_ctx *)arg;
    struct process *p = proc_current();
    if (!ctx || !ctx->suite || !p)
        proc_exit(1);

    struct kobj *send_obj = NULL;
    struct kobj *ack_recv_obj = NULL;

    if (khandle_get(p, ctx->h_send, KRIGHT_WRITE, &send_obj, NULL) < 0) {
        kh_stress_mark_error(ctx->suite);
        proc_exit(1);
    }
    if (khandle_get(p, ctx->h_ack_recv, KRIGHT_READ, &ack_recv_obj, NULL) < 0) {
        kh_stress_mark_error(ctx->suite);
        kobj_put(send_obj);
        proc_exit(1);
    }

    for (uint32_t seq = 0; seq < KH_STRESS_MSGS_PER_PRODUCER; seq++) {
        int32_t dup_h = -1;
        if (khandle_duplicate(p, ctx->h_ack_send, KRIGHT_CHANNEL_DEFAULT, &dup_h) <
            0) {
            kh_stress_mark_error(ctx->suite);
            break;
        }

        struct kobj *xfer_obj = NULL;
        uint32_t xfer_rights = 0;
        if (khandle_take(p, dup_h, KRIGHT_TRANSFER, &xfer_obj, &xfer_rights) < 0) {
            kh_stress_mark_error(ctx->suite);
            (void)khandle_close(p, dup_h);
            break;
        }

        struct kh_stress_msg msg = {
            .producer_id = ctx->producer_id,
            .seq = seq,
            .tag = KH_STRESS_TAG,
        };
        struct khandle_transfer tx = {
            .obj = xfer_obj,
            .rights = xfer_rights,
        };
        int rc = kchannel_send(send_obj, &msg, sizeof(msg), &tx, 1, 0);
        if (rc < 0) {
            int rr = khandle_restore(p, dup_h, xfer_obj, xfer_rights);
            if (rr < 0)
                khandle_transfer_drop(xfer_obj);
            kh_stress_mark_error(ctx->suite);
            break;
        }
        atomic_inc(&ctx->suite->sent);

        struct kh_stress_ack ack = {0};
        size_t got_bytes = 0;
        size_t got_handles = 0;
        bool trunc = false;
        uint64_t ack_deadline = time_now_ns() + KH_STRESS_ACK_TIMEOUT_NS;
        while (1) {
            rc = kchannel_recv(ack_recv_obj, &ack, sizeof(ack), &got_bytes, NULL, 0,
                               &got_handles, &trunc, KCHANNEL_OPT_NONBLOCK);
            if (rc == 0)
                break;
            if (rc != -EAGAIN || time_now_ns() >= ack_deadline) {
                kh_stress_mark_error(ctx->suite);
                goto out;
            }
            proc_yield();
        }
        if (got_bytes != sizeof(ack) || got_handles != 0 || trunc ||
            ack.producer_id != ctx->producer_id || ack.seq != seq) {
            kh_stress_mark_error(ctx->suite);
            break;
        }
        atomic_inc(&ctx->suite->acked);
    }

out:
    kobj_put(ack_recv_obj);
    kobj_put(send_obj);
    atomic_inc(&ctx->suite->producers_done);
    proc_exit(0);
}

static int kh_stress_consumer_worker(void *arg) {
    struct kh_stress_consumer_ctx *ctx = (struct kh_stress_consumer_ctx *)arg;
    struct process *p = proc_current();
    if (!ctx || !ctx->suite || !p)
        proc_exit(1);

    struct kobj *recv_obj = NULL;
    struct kobj *port_obj = NULL;
    if (khandle_get(p, ctx->h_recv, KRIGHT_READ, &recv_obj, NULL) < 0) {
        kh_stress_mark_error(ctx->suite);
        proc_exit(1);
    }
    if (khandle_get(p, ctx->h_port, KRIGHT_WAIT, &port_obj, NULL) < 0) {
        kh_stress_mark_error(ctx->suite);
        kobj_put(recv_obj);
        proc_exit(1);
    }

    uint64_t deadline = time_now_ns() + KH_STRESS_RUN_TIMEOUT_NS;
    while (1) {
        if (atomic_read(&ctx->suite->received) >= KH_STRESS_TOTAL_MSGS &&
            atomic_read(&ctx->suite->producers_done) >= KH_STRESS_PRODUCERS)
            break;

        struct kairos_port_packet_user pkt = {0};
        int rc = kport_wait(port_obj, &pkt, 0, KPORT_WAIT_NONBLOCK);
        if (rc == -EAGAIN) {
            if (time_now_ns() >= deadline) {
                kh_stress_mark_error(ctx->suite);
                break;
            }
            proc_yield();
            continue;
        }
        if (rc < 0) {
            kh_stress_mark_error(ctx->suite);
            break;
        }
        if ((pkt.observed & KPORT_BIND_READABLE) == 0)
            continue;

        while (1) {
            struct kh_stress_msg msg = {0};
            struct khandle_transfer rx[1] = {0};
            size_t got_bytes = 0;
            size_t got_handles = 0;
            bool trunc = false;
            rc = kchannel_recv(recv_obj, &msg, sizeof(msg), &got_bytes, rx, 1,
                               &got_handles, &trunc, KCHANNEL_OPT_NONBLOCK);
            if (rc == -EAGAIN)
                break;
            if (rc < 0) {
                kh_stress_mark_error(ctx->suite);
                goto out;
            }
            if (got_bytes == 0 && got_handles == 0)
                break;
            if (got_bytes != sizeof(msg) || got_handles != 1 || trunc ||
                !rx[0].obj || msg.tag != KH_STRESS_TAG ||
                msg.producer_id >= KH_STRESS_PRODUCERS) {
                if (rx[0].obj)
                    khandle_transfer_drop(rx[0].obj);
                kh_stress_mark_error(ctx->suite);
                goto out;
            }

            int32_t ack_h = khandle_alloc(p, rx[0].obj, rx[0].rights);
            khandle_transfer_drop(rx[0].obj);
            if (ack_h < 0) {
                kh_stress_mark_error(ctx->suite);
                goto out;
            }

            struct kobj *ack_obj = NULL;
            rc = khandle_get(p, ack_h, KRIGHT_WRITE, &ack_obj, NULL);
            if (rc < 0) {
                (void)khandle_close(p, ack_h);
                kh_stress_mark_error(ctx->suite);
                goto out;
            }

            struct kh_stress_ack ack = {
                .producer_id = msg.producer_id,
                .seq = msg.seq,
            };
            rc = kchannel_send(ack_obj, &ack, sizeof(ack), NULL, 0, 0);
            kobj_put(ack_obj);
            (void)khandle_close(p, ack_h);
            if (rc < 0) {
                kh_stress_mark_error(ctx->suite);
                goto out;
            }

            atomic_inc(&ctx->suite->received);
        }
    }

out:
    kobj_put(port_obj);
    kobj_put(recv_obj);
    proc_exit(0);
}

static struct process *create_legacy_user_process(const char *name,
                                                  const uint8_t *code,
                                                  size_t code_size,
                                                  struct process *parent) {
    struct process *p = proc_alloc_internal();
    if (!p)
        return NULL;

    bool linked_parent = false;
    strncpy(p->name, name, sizeof(p->name) - 1);
    p->uid = p->gid = 1000;
    p->syscall_abi = SYSCALL_ABI_LEGACY;

    if (parent) {
        p->parent = parent;
        p->ppid = parent->pid;
        list_add(&p->sibling, &parent->children);
        linked_parent = true;
    }

    p->mm = mm_create();
    if (!p->mm)
        goto fail;

    if (mm_add_vma(p->mm, SYSCALL_USER_TEST_CODE_ADDR,
                   SYSCALL_USER_TEST_CODE_ADDR + code_size, VM_READ | VM_EXEC,
                   NULL, 0) < 0) {
        goto fail;
    }

    for (size_t off = 0; off < code_size; off += CONFIG_PAGE_SIZE) {
        paddr_t pa = pmm_alloc_page();
        if (!pa)
            goto fail;
        memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);
        size_t remaining = code_size - off;
        size_t len = remaining < CONFIG_PAGE_SIZE ? remaining : CONFIG_PAGE_SIZE;
        memcpy(phys_to_virt(pa), code + off, len);
        if (arch_mmu_map(p->mm->pgdir, SYSCALL_USER_TEST_CODE_ADDR + off, pa,
                         PTE_USER | PTE_READ | PTE_EXEC) < 0) {
            pmm_free_page(pa);
            goto fail;
        }
    }

    vaddr_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    if (mm_add_vma(p->mm, stack_bottom, USER_STACK_TOP,
                   VM_READ | VM_WRITE | VM_STACK, NULL, 0) < 0) {
        goto fail;
    }

    for (vaddr_t va = stack_bottom; va < USER_STACK_TOP; va += CONFIG_PAGE_SIZE) {
        paddr_t pa = pmm_alloc_page();
        if (!pa)
            goto fail;
        memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);
        if (arch_mmu_map(p->mm->pgdir, va, pa, PTE_USER | PTE_READ | PTE_WRITE) <
            0) {
            pmm_free_page(pa);
            goto fail;
        }
    }

    arch_context_init(p->context, SYSCALL_USER_TEST_CODE_ADDR,
                      USER_STACK_TOP - 16, false);
    return p;

fail:
    if (linked_parent && !list_empty(&p->sibling))
        list_del(&p->sibling);
    if (p->mm)
        mm_destroy(p->mm);
    proc_free_internal(p);
    return NULL;
}

#if defined(ARCH_riscv64)
/*
 * User-mode ecall sequence:
 * 1) SYS_uname with bad pointer: expect -EFAULT
 * 2) SYS_getpid: expect > 0
 * 3) SYS_uname with stack pointer: expect 0
 * 4) SYS_exit(0)
 * failure exits with non-zero code.
 */
static const uint8_t user_syscall_e2e_prog[] = {
    0x13, 0x05, 0xf0, 0xff, 0x93, 0x08, 0x40, 0x06, 0x73, 0x00, 0x00, 0x00,
    0x93, 0x02, 0x20, 0xff, 0x63, 0x16, 0x55, 0x02, 0x93, 0x08, 0x50, 0x00,
    0x73, 0x00, 0x00, 0x00, 0x63, 0x56, 0xa0, 0x02, 0x13, 0x05, 0x01, 0xc0,
    0x93, 0x08, 0x40, 0x06, 0x73, 0x00, 0x00, 0x00, 0x63, 0x14, 0x05, 0x02,
    0x13, 0x05, 0x00, 0x00, 0x93, 0x08, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x13, 0x05, 0xb0, 0x00, 0x93, 0x08, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x13, 0x05, 0xc0, 0x00, 0x93, 0x08, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x13, 0x05, 0xd0, 0x00, 0x93, 0x08, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x6f, 0x00, 0x00, 0x00,
};
#elif defined(ARCH_x86_64)
/*
 * User-mode int 0x80 sequence:
 * 1) SYS_uname((void *)-1): expect -EFAULT
 * 2) SYS_getpid(): expect > 0
 * 3) SYS_uname(sp-0x400): expect 0
 * 4) SYS_exit(0)
 * failure exits with non-zero code.
 */
static const uint8_t user_syscall_e2e_prog[] = {
    0x48, 0xc7, 0xc7, 0xff, 0xff, 0xff, 0xff, 0x48, 0xc7, 0xc0, 0x64, 0x00,
    0x00, 0x00, 0xcd, 0x80, 0x48, 0x83, 0xf8, 0xf2, 0x75, 0x30, 0x48, 0xc7,
    0xc0, 0x05, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x48, 0x85, 0xc0, 0x7e, 0x32,
    0x48, 0x8d, 0xbc, 0x24, 0x00, 0xfc, 0xff, 0xff, 0x48, 0xc7, 0xc0, 0x64,
    0x00, 0x00, 0x00, 0xcd, 0x80, 0x48, 0x85, 0xc0, 0x75, 0x2c, 0x48, 0x31,
    0xff, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x48, 0xc7,
    0xc7, 0xb0, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
    0xcd, 0x80, 0x48, 0xc7, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0,
    0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x48, 0xc7, 0xc7, 0xd0, 0x00, 0x00,
    0x00, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80,
};
#elif defined(ARCH_aarch64)
/*
 * User-mode svc sequence:
 * 1) SYS_uname((void *)-1): expect -EFAULT
 * 2) SYS_getpid(): expect > 0
 * 3) SYS_uname(sp-0x400): expect 0
 * 4) SYS_exit(0)
 * failure exits with non-zero code.
 */
static const uint8_t user_syscall_e2e_prog[] = {
    0x00, 0x00, 0x80, 0x92, 0x88, 0x0c, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
    0xa1, 0x01, 0x80, 0x92, 0x1f, 0x00, 0x01, 0xeb, 0x81, 0x01, 0x00, 0x54,
    0xa8, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x1f, 0x00, 0x00, 0xf1,
    0x6d, 0x01, 0x00, 0x54, 0xe0, 0x03, 0x10, 0xd1, 0x88, 0x0c, 0x80, 0xd2,
    0x01, 0x00, 0x00, 0xd4, 0x40, 0x01, 0x00, 0xb5, 0x00, 0x00, 0x80, 0xd2,
    0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x16, 0x80, 0xd2,
    0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x18, 0x80, 0xd2,
    0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x1a, 0x80, 0xd2,
    0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
};
#endif

static void test_syscall_user_e2e(void) {
#if defined(ARCH_riscv64) || defined(ARCH_x86_64) || defined(ARCH_aarch64)
    struct process *parent = proc_current();
    test_check(parent != NULL, "user_e2e parent exists");
    if (!parent)
        return;

    struct process *child =
        create_legacy_user_process("sys_e2e", user_syscall_e2e_prog,
                                   sizeof(user_syscall_e2e_prog), parent);
    test_check(child != NULL, "user_e2e create child");
    if (!child)
        return;

    pid_t expected = child->pid;
    sched_enqueue(child);

    int status = 0;
    pid_t wp = 0;
    for (int i = 0; i < 4000; i++) {
        wp = proc_wait(expected, &status, WNOHANG);
        if (wp == expected || wp < 0)
            break;
        proc_yield();
    }
    if (wp == 0)
        wp = proc_wait(expected, &status, 0);

    test_check(wp == expected, "user_e2e child reaped");
    if (wp == expected)
        test_check(status == 0, "user_e2e child exit zero");
#else
    pr_info("syscall_trap_tests: user e2e skipped on unsupported arch\n");
#endif
}

static int64_t dispatch_legacy(uint64_t num, uint64_t a0, uint64_t a1,
                               uint64_t a2, uint64_t a3, uint64_t a4,
                               uint64_t a5) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    enum syscall_abi old_abi = p->syscall_abi;
    p->syscall_abi = SYSCALL_ABI_LEGACY;
    int64_t ret = syscall_dispatch(num, a0, a1, a2, a3, a4, a5);
    p->syscall_abi = old_abi;
    return ret;
}

static int trap_handle_probe(const struct trap_core_event *ev) {
    trap_handle_calls++;
    trap_handler_tf = ev ? ev->tf : NULL;
    trap_handler_saw_current_tf =
        ev && (arch_get_percpu()->current_tf == ev->tf);
    struct process *p = proc_current();
    trap_handler_saw_process_tf =
        ev && p && ((struct trap_frame *)p->active_tf == ev->tf);
    return 0;
}

static bool trap_should_deliver_false(const struct trap_core_event *ev) {
    (void)ev;
    trap_should_deliver_calls++;
    return false;
}

static void test_syscall_table_slot_coverage(void) {
    test_check(syscall_table[SYS_exit] != NULL, "table SYS_exit present");
    test_check(syscall_table[SYS_fork] != NULL, "table SYS_fork present");
    test_check(syscall_table[SYS_getpid] != NULL, "table SYS_getpid present");
    test_check(syscall_table[SYS_getppid] != NULL, "table SYS_getppid present");
    test_check(syscall_table[SYS_getuid] != NULL, "table SYS_getuid present");
    test_check(syscall_table[SYS_getgid] != NULL, "table SYS_getgid present");
    test_check(syscall_table[SYS_open] != NULL, "table SYS_open present");
    test_check(syscall_table[SYS_read] != NULL, "table SYS_read present");
    test_check(syscall_table[SYS_write] != NULL, "table SYS_write present");
    test_check(syscall_table[SYS_close] != NULL, "table SYS_close present");
    test_check(syscall_table[SYS_pipe2] != NULL, "table SYS_pipe2 present");
    test_check(syscall_table[SYS_poll] != NULL, "table SYS_poll present");
    test_check(syscall_table[SYS_clock_gettime] != NULL,
               "table SYS_clock_gettime present");
    test_check(syscall_table[SYS_uname] != NULL, "table SYS_uname present");

    test_check(syscall_table[SYS_yield] == NULL, "table SYS_yield absent");
    test_check(syscall_table[SYS_clone] == NULL, "table SYS_clone absent");
    test_check(syscall_table[SYS_mmap] == NULL, "table SYS_mmap absent");
    test_check(syscall_table[SYS_munmap] == NULL, "table SYS_munmap absent");
    test_check(syscall_table[SYS_mprotect] == NULL,
               "table SYS_mprotect absent");
}

static void test_syscall_invalid_num_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_invalid_num proc_current");
    if (!p)
        return;

    int64_t ret = dispatch_legacy(SYS_MAX, 0, 0, 0, 0, 0, 0);

    test_check(ret == -ENOSYS, "legacy_invalid_num enosys");
}

static void test_syscall_unimplemented_slot_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_unimplemented proc_current");
    if (!p)
        return;

    const uint64_t missing[] = {
        SYS_yield,
        SYS_clone,
        SYS_mmap,
        SYS_munmap,
        SYS_mprotect,
    };

    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); i++) {
        int64_t ret = dispatch_legacy(missing[i], 0, 0, 0, 0, 0, 0);
        test_check(ret == -ENOSYS, "legacy_unimplemented enosys");
    }
}

static void test_syscall_identity_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_identity proc_current");
    if (!p)
        return;

    int64_t pid = dispatch_legacy(SYS_getpid, 0, 0, 0, 0, 0, 0);
    int64_t ppid = dispatch_legacy(SYS_getppid, 0, 0, 0, 0, 0, 0);
    int64_t uid = dispatch_legacy(SYS_getuid, 0, 0, 0, 0, 0, 0);
    int64_t gid = dispatch_legacy(SYS_getgid, 0, 0, 0, 0, 0, 0);

    test_check(pid == (int64_t)p->tgid, "legacy_getpid matches_current");
    test_check(ppid == (int64_t)p->ppid, "legacy_getppid matches_current");
    test_check(uid == (int64_t)p->uid, "legacy_getuid matches_current");
    test_check(gid == (int64_t)p->gid, "legacy_getgid matches_current");
}

static void test_syscall_error_paths_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_errors proc_current");
    if (!p)
        return;

    int64_t uname_ret = dispatch_legacy(SYS_uname, 0, 0, 0, 0, 0, 0);
    test_check(uname_ret == -EFAULT, "legacy_uname null_efault");
}

static void test_uaccess_cross_page_regression(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "uaccess_cross_page proc_current");
    if (!p)
        return;

    struct mm_struct *saved_mm = p->mm;
    struct mm_struct *active_mm = saved_mm;
    struct mm_struct *temp_mm = NULL;
    paddr_t saved_pgdir = arch_mmu_current();
    bool switched_pgdir = false;

    if (!active_mm) {
        temp_mm = mm_create();
        test_check(temp_mm != NULL, "uaccess_cross_page mm_create");
        if (!temp_mm)
            return;
        p->mm = temp_mm;
        active_mm = temp_mm;
    }

    if (saved_pgdir != active_mm->pgdir) {
        arch_mmu_switch(active_mm->pgdir);
        switched_pgdir = true;
    }

    const size_t map_len = 3 * CONFIG_PAGE_SIZE;
    const size_t span = CONFIG_PAGE_SIZE + 64;
    vaddr_t map_start = 0;
    vaddr_t user_ptr = 0;

    int ret = mm_mmap(active_mm, 0, map_len, VM_READ | VM_WRITE, 0, NULL, 0,
                      false, &map_start);
    test_check(ret == 0, "uaccess_cross_page mmap");
    if (ret < 0)
        goto out_restore_mm;

    uint8_t *src = kmalloc(span);
    uint8_t *dst = kmalloc(span);
    test_check(src != NULL, "uaccess_cross_page kmalloc_src");
    test_check(dst != NULL, "uaccess_cross_page kmalloc_dst");
    if (!src || !dst)
        goto out_unmap;

    for (size_t i = 0; i < span; i++)
        src[i] = (uint8_t)((i * 131U + 7U) & 0xffU);

    user_ptr = map_start + CONFIG_PAGE_SIZE - 16;
    ret = copy_to_user((void *)user_ptr, src, span);
    test_check(ret == 0, "uaccess_cross_page copy_to_user");
    if (ret == 0) {
        vaddr_t page1 = ALIGN_DOWN(user_ptr, CONFIG_PAGE_SIZE);
        vaddr_t page2 = page1 + CONFIG_PAGE_SIZE;
        vaddr_t page3 = page2 + CONFIG_PAGE_SIZE;
        test_check(arch_mmu_translate(active_mm->pgdir, page1) != 0,
                   "uaccess_cross_page page1_faulted");
        test_check(arch_mmu_translate(active_mm->pgdir, page2) != 0,
                   "uaccess_cross_page page2_faulted");
        test_check(arch_mmu_translate(active_mm->pgdir, page3) != 0,
                   "uaccess_cross_page page3_faulted");
    }

    memset(dst, 0, span);
    ret = copy_from_user(dst, (const void *)user_ptr, span);
    test_check(ret == 0, "uaccess_cross_page copy_from_user");
    if (ret == 0)
        test_check(memcmp(src, dst, span) == 0, "uaccess_cross_page data_match");

out_unmap:
    ret = mm_munmap(active_mm, map_start, map_len);
    test_check(ret == 0, "uaccess_cross_page munmap");

    if (user_ptr && dst) {
        ret = copy_from_user(dst, (const void *)user_ptr, span);
        test_check(ret == -EFAULT, "uaccess_cross_page post_unmap_efault");
    }

    if (src)
        kfree(src);
    if (dst)
        kfree(dst);

out_restore_mm:
    if (switched_pgdir)
        arch_mmu_switch(saved_pgdir);
    if (temp_mm) {
        p->mm = saved_mm;
        mm_destroy(temp_mm);
    }
}

static void test_uaccess_large_range_regression(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "uaccess_large_range proc_current");
    if (!p)
        return;

    struct mm_struct *saved_mm = p->mm;
    struct mm_struct *active_mm = saved_mm;
    struct mm_struct *temp_mm = NULL;
    paddr_t saved_pgdir = arch_mmu_current();
    bool switched_pgdir = false;

    if (!active_mm) {
        temp_mm = mm_create();
        test_check(temp_mm != NULL, "uaccess_large_range mm_create");
        if (!temp_mm)
            return;
        p->mm = temp_mm;
        active_mm = temp_mm;
    }

    if (saved_pgdir != active_mm->pgdir) {
        arch_mmu_switch(active_mm->pgdir);
        switched_pgdir = true;
    }

    const size_t map_len = 12 * CONFIG_PAGE_SIZE;
    const size_t span = 7 * CONFIG_PAGE_SIZE + 257;
    vaddr_t map_start = 0;
    vaddr_t user_ptr = 0;

    int ret = mm_mmap(active_mm, 0, map_len, VM_READ | VM_WRITE, 0, NULL, 0,
                      false, &map_start);
    test_check(ret == 0, "uaccess_large_range mmap");
    if (ret < 0)
        goto out_restore_mm;

    uint8_t *src = kmalloc(span);
    uint8_t *dst = kmalloc(span);
    test_check(src != NULL, "uaccess_large_range kmalloc_src");
    test_check(dst != NULL, "uaccess_large_range kmalloc_dst");
    if (!src || !dst)
        goto out_unmap;

    for (size_t i = 0; i < span; i++)
        src[i] = (uint8_t)((i * 97U + 23U) & 0xffU);

    user_ptr = map_start + CONFIG_PAGE_SIZE / 2;
    ret = copy_to_user((void *)user_ptr, src, span);
    test_check(ret == 0, "uaccess_large_range copy_to_user");
    if (ret == 0) {
        vaddr_t first = ALIGN_DOWN(user_ptr, CONFIG_PAGE_SIZE);
        vaddr_t mid = first + 4 * CONFIG_PAGE_SIZE;
        vaddr_t last = ALIGN_DOWN(user_ptr + span - 1, CONFIG_PAGE_SIZE);
        test_check(arch_mmu_translate(active_mm->pgdir, first) != 0,
                   "uaccess_large_range first_faulted");
        test_check(arch_mmu_translate(active_mm->pgdir, mid) != 0,
                   "uaccess_large_range mid_faulted");
        test_check(arch_mmu_translate(active_mm->pgdir, last) != 0,
                   "uaccess_large_range last_faulted");
    }

    memset(dst, 0, span);
    ret = copy_from_user(dst, (const void *)user_ptr, span);
    test_check(ret == 0, "uaccess_large_range copy_from_user");
    if (ret == 0)
        test_check(memcmp(src, dst, span) == 0, "uaccess_large_range data_match");

    ret = mm_munmap(active_mm, map_start + 4 * CONFIG_PAGE_SIZE, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "uaccess_large_range munmap_hole");
    if (ret == 0) {
        ret = copy_from_user(dst, (const void *)user_ptr, span);
        test_check(ret == -EFAULT, "uaccess_large_range hole_copy_from_efault");

        ret = copy_to_user((void *)user_ptr, src, span);
        test_check(ret == -EFAULT, "uaccess_large_range hole_copy_to_efault");
    }

out_unmap:
    ret = mm_munmap(active_mm, map_start, map_len);
    test_check(ret == 0, "uaccess_large_range munmap_all");

    if (src)
        kfree(src);
    if (dst)
        kfree(dst);

out_restore_mm:
    if (switched_pgdir)
        arch_mmu_switch(saved_pgdir);
    if (temp_mm) {
        p->mm = saved_mm;
        mm_destroy(temp_mm);
    }
}

static void test_strncpy_from_user_len_regression(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc = user_map_begin(&um, 2 * CONFIG_PAGE_SIZE);
    test_check(rc == 0, "uaccess_strncpy user_map");
    if (rc < 0)
        return;
    mapped = true;

    char *u_cross = (char *)user_map_ptr(&um, CONFIG_PAGE_SIZE - 2);
    char *u_plain = (char *)user_map_ptr(&um, 128);
    test_check(u_cross != NULL, "uaccess_strncpy u_cross");
    test_check(u_plain != NULL, "uaccess_strncpy u_plain");
    if (!u_cross || !u_plain)
        goto out;

    static const char cross_src[] = {'A', 'B', '\0', 'X'};
    rc = copy_to_user(u_cross, cross_src, sizeof(cross_src));
    test_check(rc == 0, "uaccess_strncpy copy_cross");
    if (rc == 0) {
        char out[16];
        memset(out, 0xcc, sizeof(out));
        long len = strncpy_from_user(out, u_cross, sizeof(out));
        test_check(len == 2, "uaccess_strncpy cross_len_excludes_nul");
        test_check(out[0] == 'A' && out[1] == 'B' && out[2] == '\0',
                   "uaccess_strncpy cross_content");
    }

    static const char plain_src[] = {'1', '2', '3', '4', '\0'};
    rc = copy_to_user(u_plain, plain_src, sizeof(plain_src));
    test_check(rc == 0, "uaccess_strncpy copy_plain");
    if (rc == 0) {
        char out[8];
        memset(out, 0xcc, sizeof(out));
        long len = strncpy_from_user(out, u_plain, sizeof(plain_src));
        test_check(len == 4, "uaccess_strncpy exact_len_excludes_nul");
        test_check(out[4] == '\0', "uaccess_strncpy exact_nul_copied");
    }

    static const char nonul_src[] = {'x', 'y', 'z'};
    rc = copy_to_user(u_plain, nonul_src, sizeof(nonul_src));
    test_check(rc == 0, "uaccess_strncpy copy_nonul");
    if (rc == 0) {
        char out[8];
        memset(out, 0, sizeof(out));
        long len = strncpy_from_user(out, u_plain, sizeof(nonul_src));
        test_check(len == 3, "uaccess_strncpy nonul_len_matches_count");
        test_check(out[0] == 'x' && out[1] == 'y' && out[2] == 'z',
                   "uaccess_strncpy nonul_content");
    }

out:
    if (mapped)
        user_map_end(&um);
}

static void test_strncpy_from_user_unmapped_tail_regression(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc = user_map_begin(&um, 2 * CONFIG_PAGE_SIZE);
    test_check(rc == 0, "uaccess_strncpy_tail user_map");
    if (rc < 0)
        return;
    mapped = true;

    char *u_tail = (char *)user_map_ptr(&um, CONFIG_PAGE_SIZE - 1);
    test_check(u_tail != NULL, "uaccess_strncpy_tail u_tail");
    if (!u_tail)
        goto out;

    static const char c = 'Q';
    rc = copy_to_user(u_tail, &c, 1);
    test_check(rc == 0, "uaccess_strncpy_tail copy_char");
    if (rc == 0) {
        rc = mm_munmap(um.active_mm, um.base + CONFIG_PAGE_SIZE, CONFIG_PAGE_SIZE);
        test_check(rc == 0, "uaccess_strncpy_tail munmap_next_page");
        if (rc == 0) {
            char out[8];
            memset(out, 0, sizeof(out));
            long len = strncpy_from_user(out, u_tail, 4);
            test_check(len == -EFAULT,
                       "uaccess_strncpy_tail unmapped_tail_efault");
        }
    }

out:
    if (mapped)
        user_map_end(&um);
}

static void test_strncpy_from_user_nul_before_unmapped_tail_regression(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc = user_map_begin(&um, 2 * CONFIG_PAGE_SIZE);
    test_check(rc == 0, "uaccess_strncpy_nul_tail user_map");
    if (rc < 0)
        return;
    mapped = true;

    char *u_tail = (char *)user_map_ptr(&um, CONFIG_PAGE_SIZE - 3);
    test_check(u_tail != NULL, "uaccess_strncpy_nul_tail u_tail");
    if (!u_tail)
        goto out;

    static const char src[] = {'O', 'K', '\0'};
    rc = copy_to_user(u_tail, src, sizeof(src));
    test_check(rc == 0, "uaccess_strncpy_nul_tail copy_src");
    if (rc == 0) {
        rc = mm_munmap(um.active_mm, um.base + CONFIG_PAGE_SIZE, CONFIG_PAGE_SIZE);
        test_check(rc == 0, "uaccess_strncpy_nul_tail munmap_next_page");
        if (rc == 0) {
            char out[CONFIG_PATH_MAX];
            memset(out, 0xcc, sizeof(out));
            long len = strncpy_from_user(out, u_tail, sizeof(out));
            test_check(len == 2, "uaccess_strncpy_nul_tail len_ok");
            test_check(out[0] == 'O' && out[1] == 'K' && out[2] == '\0',
                       "uaccess_strncpy_nul_tail content_ok");
        }
    }

out:
    if (mapped)
        user_map_end(&um);
}

static void test_uaccess_arg_validation_regression(void) {
    uint8_t src = 0x5a;
    uint8_t dst = 0;
    void *bad = (void *)(~(uintptr_t)0);

    int ret = copy_from_user(&dst, bad, 1);
    test_check(ret == -EFAULT, "uaccess_arg bad_from_efault");

    ret = copy_to_user(bad, &src, 1);
    test_check(ret == -EFAULT, "uaccess_arg bad_to_efault");

    ret = copy_from_user(&dst, NULL, 0);
    test_check(ret == 0, "uaccess_arg zero_from_ok");

    ret = copy_to_user(NULL, &src, 0);
    test_check(ret == 0, "uaccess_arg zero_to_ok");
}

static void test_sched_affinity_syscalls_regression(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "affinity proc_current");
    if (!p)
        return;

    const size_t affinity_bytes = proc_sched_affinity_bytes();

    struct user_map_ctx um = {0};
    bool mapped = false;
    unsigned long saved_mask[PROC_SCHED_AFFINITY_WORDS];
    unsigned long req_mask[PROC_SCHED_AFFINITY_WORDS];
    unsigned long ext_mask[PROC_SCHED_AFFINITY_WORDS + 1];
    memset(saved_mask, 0, sizeof(saved_mask));
    memset(req_mask, 0, sizeof(req_mask));
    memset(ext_mask, 0, sizeof(ext_mask));

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "affinity user_map");
    if (rc < 0)
        goto out;
    mapped = true;

    unsigned long *u_mask = (unsigned long *)user_map_ptr(&um, 0);
    unsigned long *u_mask_ext = (unsigned long *)user_map_ptr(&um, 128);
    unsigned long *u_mask_edge =
        (unsigned long *)user_map_ptr(&um, CONFIG_PAGE_SIZE - affinity_bytes);
    test_check(u_mask != NULL, "affinity user_ptr");
    test_check(u_mask_ext != NULL, "affinity user_ptr_ext");
    test_check(u_mask_edge != NULL, "affinity user_ptr_edge");
    if (!u_mask || !u_mask_ext || !u_mask_edge)
        goto out;

    int64_t ret64 = sys_sched_getaffinity(0, affinity_bytes - 1,
                                          (uint64_t)u_mask, 0, 0, 0);
    test_check(ret64 == -EINVAL, "affinity get len_einval");

    ret64 = sys_sched_getaffinity(0, affinity_bytes, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "affinity get null_efault");

    ret64 = sys_sched_getaffinity(0, affinity_bytes, (uint64_t)u_mask, 0,
                                  0, 0);
    test_check(ret64 == (int64_t)affinity_bytes, "affinity get ok");
    if (ret64 == (int64_t)affinity_bytes) {
        rc = copy_from_user(saved_mask, u_mask, affinity_bytes);
        test_check(rc == 0, "affinity get copy_mask");
        if (rc == 0)
            test_check(!proc_sched_affinity_is_zero(saved_mask),
                       "affinity get nonzero_mask");
    }

    ret64 = sys_sched_getaffinity(0x7fffffffU, affinity_bytes,
                                  (uint64_t)u_mask, 0, 0, 0);
    test_check(ret64 == -ESRCH, "affinity get bad_pid_esrch");

    ret64 = sys_sched_setaffinity(0, affinity_bytes - 1, (uint64_t)u_mask,
                                  0, 0, 0);
    test_check(ret64 == -EINVAL, "affinity set len_einval");

    ret64 = sys_sched_setaffinity(0, affinity_bytes, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "affinity set null_efault");

    proc_sched_affinity_zero(req_mask);
    rc = copy_to_user(u_mask, req_mask, affinity_bytes);
    test_check(rc == 0, "affinity set copy_zero");
    if (rc == 0) {
        ret64 = sys_sched_setaffinity(0, affinity_bytes, (uint64_t)u_mask,
                                      0, 0, 0);
        test_check(ret64 == -EINVAL, "affinity set zero_einval");
    }

    if (!proc_sched_affinity_is_zero(saved_mask)) {
        rc = copy_to_user(u_mask, saved_mask, affinity_bytes);
        test_check(rc == 0, "affinity set copy_saved");
        if (rc == 0) {
            ret64 = sys_sched_setaffinity(0, affinity_bytes,
                                          (uint64_t)u_mask, 0, 0, 0);
            test_check(ret64 == 0, "affinity set restore_ok");
        }

        proc_sched_affinity_copy(ext_mask, saved_mask);
        ext_mask[PROC_SCHED_AFFINITY_WORDS] = 0;
        rc = copy_to_user(u_mask_ext, ext_mask, affinity_bytes + sizeof(unsigned long));
        test_check(rc == 0, "affinity set copy_ext_zero_tail");
        if (rc == 0) {
            ret64 = sys_sched_setaffinity(0, affinity_bytes + sizeof(unsigned long),
                                          (uint64_t)u_mask_ext, 0, 0, 0);
            test_check(ret64 == 0, "affinity set ext_zero_tail_ok");
        }

        ext_mask[PROC_SCHED_AFFINITY_WORDS] = 1;
        rc = copy_to_user(u_mask_ext, ext_mask, affinity_bytes + sizeof(unsigned long));
        test_check(rc == 0, "affinity set copy_ext_nonzero_tail");
        if (rc == 0) {
            ret64 = sys_sched_setaffinity(0, affinity_bytes + sizeof(unsigned long),
                                          (uint64_t)u_mask_ext, 0, 0, 0);
            test_check(ret64 == 0, "affinity set ext_nonzero_tail_ignored");
        }

        proc_sched_affinity_zero(ext_mask);
        ext_mask[PROC_SCHED_AFFINITY_WORDS] = 1;
        rc = copy_to_user(u_mask_ext, ext_mask, affinity_bytes + sizeof(unsigned long));
        test_check(rc == 0, "affinity set copy_high_only");
        if (rc == 0) {
            ret64 = sys_sched_setaffinity(0, affinity_bytes + sizeof(unsigned long),
                                          (uint64_t)u_mask_ext, 0, 0, 0);
            test_check(ret64 == -EINVAL, "affinity set high_only_einval");
        }

        rc = copy_to_user(u_mask_edge, saved_mask, affinity_bytes);
        test_check(rc == 0, "affinity set copy_edge");
        if (rc == 0) {
            ret64 = sys_sched_setaffinity(0, affinity_bytes + 1,
                                          (uint64_t)u_mask_edge, 0, 0, 0);
            test_check(ret64 == 0, "affinity set ext_tail_ignored");
        }
    }

    int cpus = sched_cpu_count();
    int bits = (int)(sizeof(unsigned long) * 8);
    int current_cpu = p->se.cpu;
    if (saved_mask[0] && cpus > 1 && current_cpu >= 0 && current_cpu < bits) {
        unsigned long alt_mask = saved_mask[0] & ~(1UL << current_cpu);
        if (alt_mask != 0) {
            proc_sched_affinity_copy(req_mask, saved_mask);
            req_mask[0] = alt_mask;
            rc = copy_to_user(u_mask, req_mask, affinity_bytes);
            test_check(rc == 0, "affinity set copy_alt");
            if (rc == 0) {
                ret64 = sys_sched_setaffinity(0, affinity_bytes,
                                              (uint64_t)u_mask, 0, 0, 0);
                test_check(ret64 == 0, "affinity set running_exclude_ok");
                if (ret64 == 0) {
                    proc_yield();
                    struct process *cur = proc_current();
                    int cur_cpu = cur ? cur->se.cpu : -1;
                    bool allowed =
                        cur_cpu >= 0 && cur_cpu < bits &&
                        ((alt_mask & (1UL << cur_cpu)) != 0);
                    test_check(allowed, "affinity set migrated_to_allowed_cpu");
                }
            }
            rc = copy_to_user(u_mask, saved_mask, affinity_bytes);
            if (rc == 0)
                (void)sys_sched_setaffinity(0, affinity_bytes,
                                            (uint64_t)u_mask, 0, 0, 0);
        }
    }

out:
    if (mapped)
        user_map_end(&um);
}

static void test_sched_policy_syscalls_regression(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "sched_policy proc_current");
    if (!p)
        return;

    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "sched_policy user_map");
    if (rc < 0)
        return;
    mapped = true;

    struct sched_param *u_param = (struct sched_param *)user_map_ptr(&um, 0);
    test_check(u_param != NULL, "sched_policy user_ptr");
    if (!u_param)
        goto out;

    int64_t ret64 = sys_sched_getscheduler(0, 0, 0, 0, 0, 0);
    test_check(ret64 == SCHED_OTHER, "sched_policy getscheduler_self_other");

    ret64 = sys_sched_getscheduler(0x7fffffffU, 0, 0, 0, 0, 0);
    test_check(ret64 == -ESRCH, "sched_policy getscheduler_badpid_esrch");

    ret64 = sys_sched_getparam(0, 0, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "sched_policy getparam_null_efault");

    struct sched_param param = {.sched_priority = 0};
    ret64 = sys_sched_getparam(0, (uint64_t)u_param, 0, 0, 0, 0);
    test_check(ret64 == 0, "sched_policy getparam_ok");
    if (ret64 == 0) {
        rc = copy_from_user(&param, u_param, sizeof(param));
        test_check(rc == 0, "sched_policy getparam_readback");
        if (rc == 0) {
            test_check(param.sched_priority == 0,
                       "sched_policy getparam_priority_zero");
        }
    }

    ret64 = sys_sched_setparam(0, 0, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "sched_policy setparam_null_efault");

    param.sched_priority = 1;
    rc = copy_to_user(u_param, &param, sizeof(param));
    test_check(rc == 0, "sched_policy setparam_copy_bad");
    if (rc == 0) {
        ret64 = sys_sched_setparam(0, (uint64_t)u_param, 0, 0, 0, 0);
        test_check(ret64 == -EINVAL, "sched_policy setparam_prio_einval");
    }

    param.sched_priority = 0;
    rc = copy_to_user(u_param, &param, sizeof(param));
    test_check(rc == 0, "sched_policy setparam_copy_zero");
    if (rc == 0) {
        ret64 = sys_sched_setparam(0, (uint64_t)u_param, 0, 0, 0, 0);
        test_check(ret64 == 0, "sched_policy setparam_ok");
    }

    ret64 = sys_sched_setscheduler(0, SCHED_FIFO, (uint64_t)u_param, 0, 0, 0);
    test_check(ret64 == -EINVAL, "sched_policy setscheduler_fifo_einval");

    ret64 = sys_sched_setscheduler(0, SCHED_OTHER, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "sched_policy setscheduler_null_efault");

    param.sched_priority = 1;
    rc = copy_to_user(u_param, &param, sizeof(param));
    test_check(rc == 0, "sched_policy setscheduler_copy_bad");
    if (rc == 0) {
        ret64 = sys_sched_setscheduler(0, SCHED_OTHER, (uint64_t)u_param,
                                       0, 0, 0);
        test_check(ret64 == -EINVAL, "sched_policy setscheduler_prio_einval");
    }

    param.sched_priority = 0;
    rc = copy_to_user(u_param, &param, sizeof(param));
    test_check(rc == 0, "sched_policy setscheduler_copy_zero");
    if (rc == 0) {
        ret64 = sys_sched_setscheduler(0, SCHED_OTHER, (uint64_t)u_param,
                                       0, 0, 0);
        test_check(ret64 == SCHED_OTHER, "sched_policy setscheduler_prev_policy");
    }

    ret64 = sys_sched_setscheduler(0, (1ULL << 32) | (uint64_t)SCHED_OTHER,
                                   (uint64_t)u_param, 0, 0, 0);
    test_check(ret64 == SCHED_OTHER, "sched_policy setscheduler_policy_width");

out:
    if (mapped)
        user_map_end(&um);
}

#define SYSCALL_MOUNT_FLAG_TEST_PATH "/tmp/.kairos_syscall_mount_flags"
#define SYSCALL_MOUNT_FLAG_TEST_NONMNT "/tmp/.kairos_syscall_umount_nonmnt"
#define SYSCALL_MOUNT_PROP_TEST_ROOT "/tmp/.kairos_mount_prop_root"
#define SYSCALL_MOUNT_PROP_TEST_CHILD "/tmp/.kairos_mount_prop_root/sub"
#define SYSCALL_MOUNT_PROP_TEST_GRANDCHILD "/tmp/.kairos_mount_prop_root/sub/leaf"
#define SYSCALL_MOUNT_PROP_TEST_CHILD_KEEP "/tmp/.kairos_mount_prop_root/sub_keep"
#define SYSCALL_MOUNT_PROP_TEST_BIND "/tmp/.kairos_mount_prop_bind"
#define SYSCALL_MOUNT_PROP_TEST_BIND_CHILD "/tmp/.kairos_mount_prop_bind/sub"
#define SYSCALL_MOUNT_PROP_TEST_BIND_GRANDCHILD "/tmp/.kairos_mount_prop_bind/sub/leaf"
#define SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP "/tmp/.kairos_mount_prop_bind/sub_keep"
#define SYSCALL_ACCT_TEST_FILE "/tmp/.kairos_syscall_acct"

static void test_mount_umount_flag_semantics(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc;

    (void)vfs_umount(SYSCALL_MOUNT_FLAG_TEST_NONMNT);
    (void)vfs_rmdir(SYSCALL_MOUNT_FLAG_TEST_NONMNT);
    (void)vfs_umount(SYSCALL_MOUNT_FLAG_TEST_PATH);
    (void)vfs_rmdir(SYSCALL_MOUNT_FLAG_TEST_PATH);

    rc = vfs_mkdir(SYSCALL_MOUNT_FLAG_TEST_PATH, 0755);
    test_check(rc == 0 || rc == -EEXIST, "mountflags mkdir");
    if (rc < 0 && rc != -EEXIST)
        goto out;
    rc = vfs_mkdir(SYSCALL_MOUNT_FLAG_TEST_NONMNT, 0755);
    test_check(rc == 0 || rc == -EEXIST, "mountflags mkdir nonmnt");
    if (rc < 0 && rc != -EEXIST)
        goto out;

    rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "mountflags user_map");
    if (rc < 0)
        goto out;
    mapped = true;

    char *u_tgt = (char *)user_map_ptr(&um, 0x000);
    char *u_fstype = (char *)user_map_ptr(&um, 0x100);
    char *u_nonmnt = (char *)user_map_ptr(&um, 0x200);
    test_check(u_tgt != NULL, "mountflags u_tgt");
    test_check(u_fstype != NULL, "mountflags u_fstype");
    test_check(u_nonmnt != NULL, "mountflags u_nonmnt");
    if (!u_tgt || !u_fstype || !u_nonmnt)
        goto out;

    rc = copy_to_user(u_tgt, SYSCALL_MOUNT_FLAG_TEST_PATH,
                      strlen(SYSCALL_MOUNT_FLAG_TEST_PATH) + 1);
    test_check(rc == 0, "mountflags copy tgt");
    rc = copy_to_user(u_nonmnt, SYSCALL_MOUNT_FLAG_TEST_NONMNT,
                      strlen(SYSCALL_MOUNT_FLAG_TEST_NONMNT) + 1);
    test_check(rc == 0, "mountflags copy nonmnt");
    rc = copy_to_user(u_fstype, "tmpfs", 6);
    test_check(rc == 0, "mountflags copy fstype");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_mount(0, (uint64_t)u_tgt, (uint64_t)u_fstype,
                              MS_RDONLY | MS_NODEV | MS_NOEXEC, 0, 0);
    test_check(ret64 == 0, "mountflags mount semantic");

    ret64 = sys_mount(0, (uint64_t)u_tgt, 0,
                      MS_REMOUNT | MS_RDONLY | MS_NOEXEC, 0, 0);
    test_check(ret64 == 0, "mountflags remount semantic");

    ret64 = sys_umount2((uint64_t)u_tgt, MNT_FORCE, 0, 0, 0, 0);
    test_check(ret64 == -EOPNOTSUPP, "mountflags umount2 force eopnotsupp");

    ret64 = sys_umount2((uint64_t)u_tgt, MNT_EXPIRE | MNT_DETACH, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "mountflags umount2 expire_detach einval");

    ret64 = sys_umount2((uint64_t)u_tgt, MNT_DETACH | UMOUNT_NOFOLLOW, 0, 0, 0, 0);
    test_check(ret64 == 0, "mountflags umount2 detach_nofollow");

    ret64 = sys_umount2((uint64_t)u_nonmnt, 0, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "mountflags umount2 nonmnt einval");

    ret64 = sys_mount(0, (uint64_t)u_tgt, (uint64_t)u_fstype, 0, 0, 0);
    test_check(ret64 == 0, "mountflags mount for expire");
    if (ret64 == 0) {
        ret64 = sys_umount2((uint64_t)u_tgt, MNT_EXPIRE, 0, 0, 0, 0);
        test_check(ret64 == -EAGAIN, "mountflags umount2 expire first eagain");

        ret64 = sys_umount2((uint64_t)u_tgt, MNT_EXPIRE, 0, 0, 0, 0);
        test_check(ret64 == 0, "mountflags umount2 expire second success");
    }

out:
    if (mapped)
        user_map_end(&um);
    (void)vfs_umount(SYSCALL_MOUNT_FLAG_TEST_NONMNT);
    (void)vfs_rmdir(SYSCALL_MOUNT_FLAG_TEST_NONMNT);
    (void)vfs_umount(SYSCALL_MOUNT_FLAG_TEST_PATH);
    (void)vfs_rmdir(SYSCALL_MOUNT_FLAG_TEST_PATH);
}

static void test_mount_propagation_recursive_semantics(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc = 0;

    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_GRANDCHILD);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_CHILD);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_GRANDCHILD);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_CHILD_KEEP);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_ROOT);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_BIND_GRANDCHILD);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_GRANDCHILD);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_CHILD);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_CHILD_KEEP);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_ROOT);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_BIND);

    rc = vfs_mkdir(SYSCALL_MOUNT_PROP_TEST_ROOT, 0755);
    test_check(rc == 0 || rc == -EEXIST, "mountprop mkdir root");
    if (rc < 0 && rc != -EEXIST)
        goto out;

    rc = vfs_mkdir(SYSCALL_MOUNT_PROP_TEST_BIND, 0755);
    test_check(rc == 0 || rc == -EEXIST, "mountprop mkdir bind");
    if (rc < 0 && rc != -EEXIST)
        goto out;

    rc = vfs_mount(NULL, SYSCALL_MOUNT_PROP_TEST_ROOT, "tmpfs", 0);
    test_check(rc == 0, "mountprop mount root");
    if (rc < 0)
        goto out;

    rc = vfs_mkdir(SYSCALL_MOUNT_PROP_TEST_CHILD, 0755);
    test_check(rc == 0 || rc == -EEXIST, "mountprop mkdir child");
    if (rc < 0 && rc != -EEXIST)
        goto out;

    rc = vfs_mount(NULL, SYSCALL_MOUNT_PROP_TEST_CHILD, "tmpfs", 0);
    test_check(rc == 0, "mountprop mount child");
    if (rc < 0)
        goto out;

    rc = vfs_mkdir(SYSCALL_MOUNT_PROP_TEST_GRANDCHILD, 0755);
    test_check(rc == 0 || rc == -EEXIST, "mountprop mkdir grandchild");
    if (rc < 0 && rc != -EEXIST)
        goto out;

    rc = vfs_mount(NULL, SYSCALL_MOUNT_PROP_TEST_GRANDCHILD, "tmpfs", 0);
    test_check(rc == 0, "mountprop mount grandchild");
    if (rc < 0)
        goto out;

    rc = vfs_mkdir(SYSCALL_MOUNT_PROP_TEST_CHILD_KEEP, 0755);
    test_check(rc == 0 || rc == -EEXIST, "mountprop mkdir child_keep");
    if (rc < 0 && rc != -EEXIST)
        goto out;

    rc = vfs_mount(NULL, SYSCALL_MOUNT_PROP_TEST_CHILD_KEEP, "tmpfs", 0);
    test_check(rc == 0, "mountprop mount child_keep");
    if (rc < 0)
        goto out;

    rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "mountprop user_map");
    if (rc < 0)
        goto out;
    mapped = true;

    char *u_root = (char *)user_map_ptr(&um, 0x000);
    char *u_bind = (char *)user_map_ptr(&um, 0x100);
    char *u_child = (char *)user_map_ptr(&um, 0x200);
    test_check(u_root != NULL, "mountprop u_root");
    test_check(u_bind != NULL, "mountprop u_bind");
    test_check(u_child != NULL, "mountprop u_child");
    if (!u_root || !u_bind || !u_child)
        goto out;

    rc = copy_to_user(u_root, SYSCALL_MOUNT_PROP_TEST_ROOT,
                      strlen(SYSCALL_MOUNT_PROP_TEST_ROOT) + 1);
    test_check(rc == 0, "mountprop copy root");
    rc = copy_to_user(u_bind, SYSCALL_MOUNT_PROP_TEST_BIND,
                      strlen(SYSCALL_MOUNT_PROP_TEST_BIND) + 1);
    test_check(rc == 0, "mountprop copy bind");
    rc = copy_to_user(u_child, SYSCALL_MOUNT_PROP_TEST_CHILD,
                      strlen(SYSCALL_MOUNT_PROP_TEST_CHILD) + 1);
    test_check(rc == 0, "mountprop copy child");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_mount(0, (uint64_t)u_root, 0, MS_SHARED | MS_REC, 0, 0);
    test_check(ret64 == 0, "mountprop shared rec");
    if (ret64 == 0) {
        struct mount *root_mnt = vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_ROOT);
        struct mount *child_mnt = vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_CHILD);
        struct mount *grandchild_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_GRANDCHILD);
        test_check(root_mnt != NULL, "mountprop root mnt shared");
        test_check(child_mnt != NULL, "mountprop child mnt shared");
        test_check(grandchild_mnt != NULL, "mountprop grandchild mnt shared");
        if (root_mnt)
            test_check(root_mnt->prop == MOUNT_SHARED, "mountprop root shared");
        if (child_mnt)
            test_check(child_mnt->prop == MOUNT_SHARED, "mountprop child shared");
        if (grandchild_mnt)
            test_check(grandchild_mnt->prop == MOUNT_SHARED,
                       "mountprop grandchild shared");
    }

    ret64 = sys_mount(0, (uint64_t)u_root, 0, MS_PRIVATE, 0, 0);
    test_check(ret64 == 0, "mountprop private nonrec");
    if (ret64 == 0) {
        struct mount *root_mnt = vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_ROOT);
        struct mount *child_mnt = vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_CHILD);
        struct mount *grandchild_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_GRANDCHILD);
        test_check(root_mnt != NULL, "mountprop root mnt private");
        test_check(child_mnt != NULL, "mountprop child mnt private");
        test_check(grandchild_mnt != NULL, "mountprop grandchild mnt private");
        if (root_mnt)
            test_check(root_mnt->prop == MOUNT_PRIVATE, "mountprop root private");
        if (child_mnt)
            test_check(child_mnt->prop == MOUNT_SHARED,
                       "mountprop child unchanged without rec");
        if (grandchild_mnt)
            test_check(grandchild_mnt->prop == MOUNT_SHARED,
                       "mountprop grandchild unchanged without rec");
    }

    ret64 = sys_mount((uint64_t)u_root, (uint64_t)u_bind, 0, MS_BIND, 0, 0);
    test_check(ret64 == 0, "mountprop bind nonrec");
    if (ret64 == 0) {
        struct mount *bind_sub_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD);
        test_check(bind_sub_mnt != NULL, "mountprop bind nonrec sub lookup");
        if (bind_sub_mnt)
            test_check(strcmp(bind_sub_mnt->mountpoint,
                              SYSCALL_MOUNT_PROP_TEST_BIND) == 0,
                       "mountprop bind nonrec sub not mounted");
        struct mount *bind_keep_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP);
        test_check(bind_keep_mnt != NULL, "mountprop bind nonrec keep lookup");
        if (bind_keep_mnt)
            test_check(strcmp(bind_keep_mnt->mountpoint,
                              SYSCALL_MOUNT_PROP_TEST_BIND) == 0,
                       "mountprop bind nonrec keep not mounted");
        (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND);
    }

    ret64 = sys_mount((uint64_t)u_root, (uint64_t)u_bind, 0,
                      MS_BIND | MS_REC, 0, 0);
    test_check(ret64 == 0, "mountprop bind rec");
    if (ret64 == 0) {
        struct mount *bind_sub_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD);
        struct mount *bind_grandchild_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_BIND_GRANDCHILD);
        struct mount *bind_keep_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP);
        test_check(bind_sub_mnt != NULL, "mountprop bind rec sub lookup");
        test_check(bind_grandchild_mnt != NULL,
                   "mountprop bind rec grandchild lookup");
        test_check(bind_keep_mnt != NULL, "mountprop bind rec keep lookup");
        if (bind_sub_mnt)
            test_check(strcmp(bind_sub_mnt->mountpoint,
                              SYSCALL_MOUNT_PROP_TEST_BIND_CHILD) == 0,
                       "mountprop bind rec sub mounted");
        if (bind_grandchild_mnt)
            test_check(strcmp(bind_grandchild_mnt->mountpoint,
                              SYSCALL_MOUNT_PROP_TEST_BIND_GRANDCHILD) == 0,
                       "mountprop bind rec grandchild mounted");
        if (bind_keep_mnt)
            test_check(strcmp(bind_keep_mnt->mountpoint,
                              SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP) == 0,
                       "mountprop bind rec keep mounted");
        (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_GRANDCHILD);
        (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP);
        (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD);
        (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND);
    }

    ret64 = sys_mount(0, (uint64_t)u_root, 0, MS_PRIVATE | MS_REC, 0, 0);
    test_check(ret64 == 0, "mountprop private rec");

    ret64 = sys_mount(0, (uint64_t)u_child, 0, MS_UNBINDABLE, 0, 0);
    test_check(ret64 == 0, "mountprop child unbindable");
    if (ret64 == 0) {
        struct mount *child_mnt = vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_CHILD);
        test_check(child_mnt != NULL, "mountprop child mnt unbindable-only");
        if (child_mnt)
            test_check(child_mnt->prop == MOUNT_UNBINDABLE,
                       "mountprop child unbindable-only prop");
    }

    ret64 = sys_mount((uint64_t)u_root, (uint64_t)u_bind, 0,
                      MS_BIND | MS_REC, 0, 0);
    test_check(ret64 == 0, "mountprop bind rec prune unbindable");
    if (ret64 == 0) {
        struct mount *bind_sub_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD);
        struct mount *bind_grandchild_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_BIND_GRANDCHILD);
        struct mount *bind_keep_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP);
        test_check(bind_sub_mnt != NULL, "mountprop prune sub lookup");
        test_check(bind_grandchild_mnt != NULL,
                   "mountprop prune grandchild lookup");
        test_check(bind_keep_mnt != NULL, "mountprop prune keep lookup");
        if (bind_sub_mnt)
            test_check(strcmp(bind_sub_mnt->mountpoint,
                              SYSCALL_MOUNT_PROP_TEST_BIND) == 0,
                       "mountprop prune unbindable sub skipped");
        if (bind_grandchild_mnt)
            test_check(strcmp(bind_grandchild_mnt->mountpoint,
                              SYSCALL_MOUNT_PROP_TEST_BIND) == 0,
                       "mountprop prune unbindable grandchild skipped");
        if (bind_keep_mnt)
            test_check(strcmp(bind_keep_mnt->mountpoint,
                              SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP) == 0,
                       "mountprop prune keep mounted");
        (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP);
        (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND);
    }

    ret64 = sys_mount(0, (uint64_t)u_root, 0, MS_UNBINDABLE | MS_REC, 0, 0);
    test_check(ret64 == 0, "mountprop unbindable rec");
    if (ret64 == 0) {
        struct mount *root_mnt = vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_ROOT);
        struct mount *child_mnt = vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_CHILD);
        struct mount *grandchild_mnt =
            vfs_mount_for_path(SYSCALL_MOUNT_PROP_TEST_GRANDCHILD);
        test_check(root_mnt != NULL, "mountprop root mnt unbindable");
        test_check(child_mnt != NULL, "mountprop child mnt unbindable");
        test_check(grandchild_mnt != NULL, "mountprop grandchild mnt unbindable");
        if (root_mnt)
            test_check(root_mnt->prop == MOUNT_UNBINDABLE,
                       "mountprop root unbindable");
        if (child_mnt)
            test_check(child_mnt->prop == MOUNT_UNBINDABLE,
                       "mountprop child unbindable");
        if (grandchild_mnt)
            test_check(grandchild_mnt->prop == MOUNT_UNBINDABLE,
                       "mountprop grandchild unbindable");
    }

    ret64 = sys_mount((uint64_t)u_root, (uint64_t)u_bind, 0, MS_BIND, 0, 0);
    test_check(ret64 == -EINVAL, "mountprop bind from unbindable einval");

    ret64 = sys_mount(0, (uint64_t)u_root, 0, MS_SHARED | MS_PRIVATE, 0, 0);
    test_check(ret64 == -EINVAL, "mountprop multi propagation bits einval");

out:
    if (mapped)
        user_map_end(&um);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_GRANDCHILD);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_BIND);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_GRANDCHILD);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_CHILD);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_CHILD_KEEP);
    (void)vfs_umount(SYSCALL_MOUNT_PROP_TEST_ROOT);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_BIND_GRANDCHILD);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_BIND_CHILD_KEEP);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_GRANDCHILD);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_CHILD);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_CHILD_KEEP);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_ROOT);
    (void)vfs_rmdir(SYSCALL_MOUNT_PROP_TEST_BIND);
}

static void test_acct_syscall_semantics(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "acct proc_current");
    if (!p)
        return;

    uid_t saved_uid = p->uid;
    struct user_map_ctx um = {0};
    bool mapped = false;
    struct file *f = NULL;

    int rc = vfs_open(SYSCALL_ACCT_TEST_FILE, O_CREAT | O_TRUNC | O_RDWR, 0644, &f);
    test_check(rc == 0, "acct create file");
    if (rc == 0 && f)
        vfs_close(f);

    rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "acct user_map");
    if (rc < 0)
        goto out_restore_uid;
    mapped = true;

    char *u_path = (char *)user_map_ptr(&um, 0x000);
    char *u_dir = (char *)user_map_ptr(&um, 0x100);
    test_check(u_path != NULL, "acct u_path");
    test_check(u_dir != NULL, "acct u_dir");
    if (!u_path || !u_dir)
        goto out;

    rc = copy_to_user(u_path, SYSCALL_ACCT_TEST_FILE, strlen(SYSCALL_ACCT_TEST_FILE) + 1);
    test_check(rc == 0, "acct copy file");
    rc = copy_to_user(u_dir, "/tmp", 5);
    test_check(rc == 0, "acct copy dir");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_acct((uint64_t)u_path, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "acct enable root");

    ret64 = sys_acct(0, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "acct disable root");

    ret64 = sys_acct((uint64_t)u_dir, 0, 0, 0, 0, 0);
    test_check(ret64 == -EISDIR, "acct dir eisdir");

    ret64 = sys_acct(0x1000, 0, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "acct badptr efault");

    p->uid = 1000;
    ret64 = sys_acct((uint64_t)u_path, 0, 0, 0, 0, 0);
    test_check(ret64 == -EPERM, "acct nonroot eperm");
    p->uid = saved_uid;

out:
    if (mapped)
        user_map_end(&um);
out_restore_uid:
    p->uid = saved_uid;
    (void)vfs_unlink(SYSCALL_ACCT_TEST_FILE);
}

static void test_futex_waitv_syscalls_regression(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "futex_waitv user_map");
    if (rc < 0)
        goto out;
    mapped = true;

    uint32_t *u_word = (uint32_t *)user_map_ptr(&um, 0);
    struct futex_waitv *u_waiter =
        (struct futex_waitv *)user_map_ptr(&um, 64);
    struct timespec *u_timeout =
        (struct timespec *)user_map_ptr(&um, 128);
    test_check(u_word != NULL, "futex_waitv u_word");
    test_check(u_waiter != NULL, "futex_waitv u_waiter");
    test_check(u_timeout != NULL, "futex_waitv u_timeout");
    if (!u_word || !u_waiter || !u_timeout)
        goto out;

    uint32_t word = 0;
    rc = copy_to_user(u_word, &word, sizeof(word));
    test_check(rc == 0, "futex_waitv init_word");
    if (rc < 0)
        goto out;

    struct futex_waitv waiter = {
        .val = 0,
        .uaddr = (uint64_t)(uintptr_t)u_word,
        .flags = FUTEX_32,
        .__reserved = 0,
    };
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv init_waiter");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_futex_waitv(0, 1, 0, 0, CLOCK_MONOTONIC, 0);
    test_check(ret64 == -EFAULT, "futex_waitv null_waiters_efault");

    ret64 = sys_futex_waitv((uint64_t)u_waiter, 0, 0, 0, CLOCK_MONOTONIC, 0);
    test_check(ret64 == -EINVAL, "futex_waitv nr_zero_einval");

    ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 1, 0, CLOCK_MONOTONIC, 0);
    test_check(ret64 == -EINVAL, "futex_waitv flags_einval");

    waiter.flags = 0;
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv copy_bad_flags");
    if (rc == 0) {
        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, 0, CLOCK_MONOTONIC, 0);
        test_check(ret64 == -EINVAL, "futex_waitv waiter_flags_einval");
    }

    waiter.flags = FUTEX_32;
    waiter.__reserved = 1;
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv copy_reserved");
    if (rc == 0) {
        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, 0, CLOCK_MONOTONIC, 0);
        test_check(ret64 == -EINVAL, "futex_waitv reserved_einval");
    }

    waiter.__reserved = 0;
    waiter.val = 1;
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv copy_eagain_waiter");
    if (rc == 0) {
        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, 0, CLOCK_MONOTONIC, 0);
        test_check(ret64 == -EAGAIN, "futex_waitv value_mismatch_eagain");
    }

    waiter.val = 0;
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv copy_timeout_waiter");
    if (rc == 0) {
        uint64_t now_ns = time_now_ns();
        struct timespec abs = ns_to_timespec(now_ns);
        rc = copy_to_user(u_timeout, &abs, sizeof(abs));
        test_check(rc == 0, "futex_waitv copy_timeout_now");
        if (rc == 0) {
            ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, (uint64_t)u_timeout,
                                    CLOCK_MONOTONIC, 0);
            test_check(ret64 == -ETIMEDOUT, "futex_waitv timeout_etimedout");
        }

        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, (uint64_t)u_timeout,
                                12345, 0);
        test_check(ret64 == -EINVAL, "futex_waitv bad_clock_einval");
    }

    struct futex_waker_ctx wctx = {
        .uaddr = (vaddr_t)u_word,
        .started = 0,
        .wake_ret = 0,
    };
    struct process *waker =
        kthread_create_joinable(futex_waitv_waker_worker, &wctx, "fwaitv");
    test_check(waker != NULL, "futex_waitv create_waker");
    if (!waker)
        goto out;
    pid_t wpid = waker->pid;
    sched_enqueue(waker);
    for (int i = 0; i < 2000 && !wctx.started; i++)
        proc_yield();
    test_check(wctx.started != 0, "futex_waitv waker_started");

    uint64_t wake_deadline_ns = time_now_ns() + 1000ULL * 1000ULL * 1000ULL;
    struct timespec wake_abs = ns_to_timespec(wake_deadline_ns);
    rc = copy_to_user(u_timeout, &wake_abs, sizeof(wake_abs));
    test_check(rc == 0, "futex_waitv copy_wake_timeout");
    if (rc == 0) {
        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, (uint64_t)u_timeout,
                                CLOCK_MONOTONIC, 0);
        test_check(ret64 == 0, "futex_waitv wake_index_zero");
    }

    int status = 0;
    pid_t wp = proc_wait(wpid, &status, 0);
    test_check(wp == wpid, "futex_waitv waker_reaped");
    test_check(wctx.wake_ret > 0, "futex_waitv wake_positive");

out:
    if (mapped)
        user_map_end(&um);
}

static void test_trap_dispatch_guard_clauses(void) {
    struct trap_frame tf;
    memset(&tf, 0, sizeof(tf));

    struct trap_core_event ev = {
        .type = TRAP_CORE_EVENT_SYSCALL,
        .tf = &tf,
        .from_user = false,
        .code = 0,
        .fault_addr = 0,
    };
    struct trap_core_ops ops = {
        .handle_event = trap_handle_probe,
        .should_deliver_signals = trap_should_deliver_false,
    };
    struct trap_core_ops ops_no_handler = {
        .handle_event = NULL,
        .should_deliver_signals = trap_should_deliver_false,
    };

    trap_handle_calls = 0;
    trap_should_deliver_calls = 0;

    trap_core_dispatch(NULL, &ops);
    trap_core_dispatch(&ev, NULL);
    trap_core_dispatch(&ev, &ops_no_handler);
    ev.tf = NULL;
    trap_core_dispatch(&ev, &ops);

    test_check(trap_handle_calls == 0, "trap_guard no_handle_calls");
    test_check(trap_should_deliver_calls == 0, "trap_guard no_deliver_calls");
}

static void test_trap_dispatch_sets_and_restores_tf(void) {
    struct trap_frame tf;
    memset(&tf, 0, sizeof(tf));

    struct trap_core_event ev = {
        .type = TRAP_CORE_EVENT_SYSCALL,
        .tf = &tf,
        .from_user = false,
        .code = 0,
        .fault_addr = 0,
    };
    struct trap_core_ops ops = {
        .handle_event = trap_handle_probe,
        .should_deliver_signals = trap_should_deliver_false,
    };

    struct percpu_data *cpu = arch_get_percpu();
    struct process *p = proc_current();
    struct trap_frame *old_tf = cpu->current_tf;
    void *old_proc_tf = p ? p->active_tf : NULL;

    trap_handle_calls = 0;
    trap_should_deliver_calls = 0;
    trap_handler_saw_current_tf = false;
    trap_handler_saw_process_tf = false;
    trap_handler_tf = NULL;

    trap_core_dispatch(&ev, &ops);

    test_check(trap_handle_calls == 1, "trap_dispatch handle_called");
    test_check(trap_should_deliver_calls == 1, "trap_dispatch deliver_called");
    test_check(trap_handler_tf == &tf, "trap_dispatch handler_tf");
    test_check(trap_handler_saw_current_tf, "trap_dispatch saw_current_tf");
    test_check(trap_handler_saw_process_tf, "trap_dispatch saw_process_tf");
    test_check(cpu->current_tf == old_tf, "trap_dispatch restored_tf");
    if (p)
        test_check(p->active_tf == old_proc_tf,
                   "trap_dispatch restored_process_tf");
}

static void test_trap_dispatch_restores_preexisting_tf(void) {
    struct trap_frame tf;
    struct trap_frame injected_old;
    memset(&tf, 0, sizeof(tf));
    memset(&injected_old, 0, sizeof(injected_old));

    struct trap_core_event ev = {
        .type = TRAP_CORE_EVENT_PAGE_FAULT,
        .tf = &tf,
        .from_user = true,
        .code = 1,
        .fault_addr = 0x1000,
    };
    struct trap_core_ops ops = {
        .handle_event = trap_handle_probe,
        .should_deliver_signals = trap_should_deliver_false,
    };

    struct percpu_data *cpu = arch_get_percpu();
    struct process *p = proc_current();
    struct trap_frame *saved = cpu->current_tf;
    void *saved_proc_tf = p ? p->active_tf : NULL;
    cpu->current_tf = &injected_old;
    if (p)
        p->active_tf = &injected_old;

    trap_handle_calls = 0;
    trap_should_deliver_calls = 0;
    trap_handler_saw_current_tf = false;
    trap_handler_saw_process_tf = false;
    trap_handler_tf = NULL;

    trap_core_dispatch(&ev, &ops);

    test_check(trap_handle_calls == 1, "trap_restore_nonnull handle_called");
    test_check(trap_should_deliver_calls == 1,
               "trap_restore_nonnull deliver_called");
    test_check(trap_handler_tf == &tf, "trap_restore_nonnull handler_tf");
    test_check(trap_handler_saw_current_tf, "trap_restore_nonnull saw_current");
    test_check(trap_handler_saw_process_tf,
               "trap_restore_nonnull saw_process");
    test_check(cpu->current_tf == &injected_old,
               "trap_restore_nonnull restored_previous");
    if (p)
        test_check(p->active_tf == &injected_old,
                   "trap_restore_nonnull restored_process");

    cpu->current_tf = saved;
    if (p)
        p->active_tf = saved_proc_tf;
}

static void test_get_current_trapframe_process_fallback(void) {
    struct process *p = proc_current();
    struct percpu_data *cpu = arch_get_percpu();
    test_check(p != NULL, "trap_tf_fallback proc_current");
    test_check(cpu != NULL, "trap_tf_fallback percpu");
    if (!p || !cpu)
        return;

    struct trap_frame probe;
    memset(&probe, 0, sizeof(probe));

    struct trap_frame *saved_cpu_tf = cpu->current_tf;
    void *saved_proc_tf = p->active_tf;

    cpu->current_tf = NULL;
    p->active_tf = &probe;
    test_check(get_current_trapframe() == &probe,
               "trap_tf_fallback active_tf_used");

    p->active_tf = NULL;
    test_check(get_current_trapframe() == NULL,
               "trap_tf_fallback null_when_missing");

    p->active_tf = saved_proc_tf;
    cpu->current_tf = saved_cpu_tf;
}

static void test_kairos_cap_rights_fd_syscalls(void) {
    enum { TEST_F_SETFL = 4 };
    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "cap_rights_fd user_map");
    if (rc < 0)
        return;
    mapped = true;

    int32_t *u_fds = (int32_t *)user_map_ptr(&um, 0x40);
    uint64_t *u_rights = (uint64_t *)user_map_ptr(&um, 0x80);
    int *u_on = (int *)user_map_ptr(&um, 0xC0);
    uint8_t *u_dummy = (uint8_t *)user_map_ptr(&um, 0x100);
    test_check(u_fds && u_rights && u_on && u_dummy, "cap_rights_fd user ptrs");
    if (!u_fds || !u_rights || !u_on || !u_dummy)
        goto out;

    int32_t fds[2] = {-1, -1};
    int64_t ret64 = sys_pipe2((uint64_t)u_fds, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "cap_rights_fd pipe2");
    if (ret64 < 0)
        goto out;

    rc = copy_from_user(fds, u_fds, sizeof(fds));
    test_check(rc == 0, "cap_rights_fd copy pipe fds");
    if (rc < 0)
        goto out_close;

    int on = 1;
    rc = copy_to_user(u_on, &on, sizeof(on));
    test_check(rc == 0, "cap_rights_fd copy ioctl arg");
    if (rc < 0)
        goto out_close;

    ret64 = sys_kairos_cap_rights_get((uint64_t)fds[1], (uint64_t)u_rights, 0, 0,
                                      0, 0);
    test_check(ret64 == 0, "cap_rights_fd get write_end rights");
    uint64_t wr_rights = 0;
    if (ret64 == 0) {
        rc = copy_from_user(&wr_rights, u_rights, sizeof(wr_rights));
        test_check(rc == 0, "cap_rights_fd read write_end rights");
        if (rc == 0) {
            test_check((wr_rights & FD_RIGHT_WRITE) != 0,
                       "cap_rights_fd write_end has write");
            test_check((wr_rights & FD_RIGHT_IOCTL) != 0,
                       "cap_rights_fd write_end has ioctl");
        }
    }

    ret64 = sys_kairos_cap_rights_limit((uint64_t)fds[1], FD_RIGHT_IOCTL, 0, 0, 0,
                                        0);
    test_check(ret64 == 0, "cap_rights_fd limit write_end ioctl_only");

    ret64 = sys_kairos_cap_rights_get((uint64_t)fds[1], (uint64_t)u_rights, 0, 0,
                                      0, 0);
    test_check(ret64 == 0, "cap_rights_fd get write_end rights limited");
    if (ret64 == 0) {
        rc = copy_from_user(&wr_rights, u_rights, sizeof(wr_rights));
        test_check(rc == 0, "cap_rights_fd read write_end rights limited");
        if (rc == 0) {
            test_check((wr_rights & FD_RIGHT_WRITE) == 0,
                       "cap_rights_fd write_end write removed");
            test_check((wr_rights & FD_RIGHT_IOCTL) != 0,
                       "cap_rights_fd write_end ioctl kept");
        }
    }

    ret64 = sys_ioctl((uint64_t)fds[1], (uint64_t)FIONBIO, (uint64_t)u_on, 0, 0,
                      0);
    test_check(ret64 == 0, "cap_rights_fd ioctl allowed");

    ret64 = sys_fcntl((uint64_t)fds[1], (uint64_t)TEST_F_SETFL,
                      (uint64_t)O_NONBLOCK, 0, 0, 0);
    test_check(ret64 == 0, "cap_rights_fd fcntl setfl allowed with ioctl");

    ret64 = sys_write((uint64_t)fds[1], (uint64_t)u_dummy, 0, 0, 0, 0);
    test_check(ret64 == -EBADF, "cap_rights_fd write denied after limit");

    int64_t dupfd = sys_dup((uint64_t)fds[0], 0, 0, 0, 0, 0);
    test_check(dupfd >= 0, "cap_rights_fd dup read_end");
    if (dupfd >= 0) {
        ret64 = sys_kairos_cap_rights_limit((uint64_t)dupfd, FD_RIGHT_READ, 0, 0,
                                            0, 0);
        test_check(ret64 == 0, "cap_rights_fd limit dupfd read_only");
        ret64 = sys_fcntl((uint64_t)dupfd, (uint64_t)TEST_F_SETFL,
                          (uint64_t)O_NONBLOCK, 0, 0, 0);
        test_check(ret64 == -EBADF,
                   "cap_rights_fd fcntl setfl denied without ioctl");
        (void)sys_close((uint64_t)dupfd, 0, 0, 0, 0, 0);
    }

    ret64 = sys_kairos_cap_rights_limit((uint64_t)fds[0], FD_RIGHT_IOCTL, 0, 0, 0,
                                        0);
    test_check(ret64 == 0, "cap_rights_fd limit read_end ioctl_only");

    ret64 = sys_read((uint64_t)fds[0], (uint64_t)u_dummy, 0, 0, 0, 0);
    test_check(ret64 == -EBADF, "cap_rights_fd read denied after limit");

    ret64 = sys_ioctl((uint64_t)fds[0], (uint64_t)FIONBIO, (uint64_t)u_on, 0, 0,
                      0);
    test_check(ret64 == 0, "cap_rights_fd read_end ioctl allowed");

    ret64 = sys_kairos_cap_rights_limit((uint64_t)fds[0], (1ULL << 20), 0, 0, 0,
                                        0);
    test_check(ret64 == -EINVAL, "cap_rights_fd limit rejects unknown bits");

out_close:
    if (fds[0] >= 0)
        (void)sys_close((uint64_t)fds[0], 0, 0, 0, 0, 0);
    if (fds[1] >= 0)
        (void)sys_close((uint64_t)fds[1], 0, 0, 0, 0, 0);
out:
    if (mapped)
        user_map_end(&um);
}

static void test_kairos_channel_port_syscalls(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;

    int32_t h0 = -1;
    int32_t h1 = -1;
    int32_t h2a = -1;
    int32_t h2b = -1;
    int32_t port = -1;
    int32_t port_fd = -1;
    int32_t port_nb_fd = -1;
    int32_t port_from_fd_h = -1;
    int32_t port_manage_h = -1;
    int32_t port_manage_fd = -1;
    int32_t port_manage_from_fd_h = -1;
    int32_t ch_fd = -1;
    int32_t ch_nb_fd = -1;
    int32_t ch_ro_h = -1;
    int32_t ch_ro_fd = -1;
    int32_t ch_wo_h = -1;
    int32_t ch_wo_fd = -1;
    int32_t ch_from_fd_h = -1;
    int32_t recv_h = -1;
    int32_t dup_h = -1;
    int32_t drop_h = -1;

    int ret = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "kh user map");
    if (ret < 0)
        return;
    mapped = true;

    int32_t *u_h0 = (int32_t *)user_map_ptr(&um, 0x000);
    int32_t *u_h1 = (int32_t *)user_map_ptr(&um, 0x008);
    int32_t *u_hout = (int32_t *)user_map_ptr(&um, 0x010);
    int32_t *u_send_handles = (int32_t *)user_map_ptr(&um, 0x020);
    int32_t *u_recv_handles = (int32_t *)user_map_ptr(&um, 0x040);
    struct kairos_channel_msg_user *u_send_msg =
        (struct kairos_channel_msg_user *)user_map_ptr(&um, 0x080);
    struct kairos_channel_msg_user *u_recv_msg =
        (struct kairos_channel_msg_user *)user_map_ptr(&um, 0x0C0);
    struct kairos_port_packet_user *u_pkt =
        (struct kairos_port_packet_user *)user_map_ptr(&um, 0x100);
    char *u_send_bytes = (char *)user_map_ptr(&um, 0x180);
    char *u_recv_bytes = (char *)user_map_ptr(&um, 0x200);
    struct pollfd *u_pollfd = (struct pollfd *)user_map_ptr(&um, 0x240);
    test_check(u_h0 && u_h1 && u_hout && u_send_handles && u_recv_handles &&
                   u_send_msg && u_recv_msg && u_pkt && u_send_bytes &&
                   u_recv_bytes && u_pollfd,
               "kh user ptr");
    if (!u_h0 || !u_h1 || !u_hout || !u_send_handles || !u_recv_handles ||
        !u_send_msg || !u_recv_msg || !u_pkt || !u_send_bytes || !u_recv_bytes ||
        !u_pollfd)
        goto out;

    int64_t ret64 =
        sys_kairos_channel_create((uint64_t)u_h0, (uint64_t)u_h1, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh channel_create");
    if (ret64 < 0)
        goto out;
    ret = copy_from_user(&h0, u_h0, sizeof(h0));
    test_check(ret == 0, "kh read h0");
    ret = copy_from_user(&h1, u_h1, sizeof(h1));
    test_check(ret == 0, "kh read h1");
    if (ret < 0)
        goto out;

    ret64 = sys_kairos_channel_create((uint64_t)u_h0, (uint64_t)u_h1, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh channel_create transfer_pair");
    if (ret64 < 0)
        goto out;
    ret = copy_from_user(&h2a, u_h0, sizeof(h2a));
    test_check(ret == 0, "kh read h2a");
    ret = copy_from_user(&h2b, u_h1, sizeof(h2b));
    test_check(ret == 0, "kh read h2b");
    if (ret < 0)
        goto out;

    ret64 = sys_kairos_port_create((uint64_t)u_hout, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh port_create");
    if (ret64 < 0)
        goto out;
    ret = copy_from_user(&port, u_hout, sizeof(port));
    test_check(ret == 0, "kh read port");
    if (ret < 0)
        goto out;

    ret64 = sys_kairos_port_bind((uint64_t)port, (uint64_t)h1, 0x55,
                                 KPORT_BIND_READABLE | KPORT_BIND_PEER_CLOSED, 0,
                                 0);
    test_check(ret64 == 0, "kh port_bind");
    if (ret64 < 0)
        goto out;

    ret64 = sys_kairos_fd_from_handle((uint64_t)port, (uint64_t)u_hout, 0, 0, 0,
                                      0);
    test_check(ret64 == 0, "kh fd_from_handle port");
    if (ret64 < 0)
        goto out;
    ret = copy_from_user(&port_fd, u_hout, sizeof(port_fd));
    test_check(ret == 0, "kh read port fd");
    if (ret < 0)
        goto out;

    ret64 = sys_kairos_handle_duplicate((uint64_t)port,
                                        KRIGHT_MANAGE | KRIGHT_DUPLICATE,
                                        (uint64_t)u_hout, 0, 0, 0);
    test_check(ret64 == 0, "kh duplicate port manage_only");
    if (ret64 == 0) {
        ret = copy_from_user(&port_manage_h, u_hout, sizeof(port_manage_h));
        test_check(ret == 0, "kh read port manage_only handle");
        if (ret < 0)
            goto out;
    }

    if (port_manage_h >= 0) {
        ret64 = sys_kairos_fd_from_handle((uint64_t)port_manage_h,
                                          (uint64_t)u_hout, 0, 0, 0, 0);
        test_check(ret64 == 0, "kh fd_from_handle port manage_only");
        if (ret64 == 0) {
            ret = copy_from_user(&port_manage_fd, u_hout, sizeof(port_manage_fd));
            test_check(ret == 0, "kh read port manage_only fd");
            if (ret < 0)
                goto out;
        }

        if (port_manage_fd >= 0) {
            ret64 = sys_read((uint64_t)port_manage_fd, (uint64_t)u_pkt,
                             sizeof(*u_pkt), 0, 0, 0);
            test_check(ret64 == -EBADF, "kh port manage_only fd read denied");

            struct pollfd pmfd = {
                .fd = port_manage_fd,
                .events = POLLIN,
                .revents = 0,
            };
            ret = copy_to_user(u_pollfd, &pmfd, sizeof(pmfd));
            test_check(ret == 0, "kh copy pollfd port manage_only");
            if (ret < 0)
                goto out;
            ret64 = sys_poll((uint64_t)u_pollfd, 1, 0, 0, 0, 0);
            test_check(ret64 == 0, "kh poll port manage_only suppress pollin");
            if (ret64 == 0) {
                ret = copy_from_user(&pmfd, u_pollfd, sizeof(pmfd));
                test_check(ret == 0, "kh read pollfd port manage_only");
                if (ret == 0)
                    test_check(pmfd.revents == 0,
                               "kh poll revents clear port manage_only");
            }

            ret64 = sys_kairos_handle_from_fd((uint64_t)port_manage_fd,
                                              (uint64_t)u_hout, 0, 0, 0, 0);
            test_check(ret64 == 0, "kh handle_from_fd port manage_only");
            if (ret64 == 0) {
                ret = copy_from_user(&port_manage_from_fd_h, u_hout,
                                     sizeof(port_manage_from_fd_h));
                test_check(ret == 0, "kh read port manage_only handle from fd");
                if (ret < 0)
                    goto out;
            }
        }

        if (port_manage_from_fd_h >= 0) {
            ret64 = sys_kairos_port_wait((uint64_t)port_manage_from_fd_h,
                                         (uint64_t)u_pkt, 0, KPORT_WAIT_NONBLOCK,
                                         0, 0);
            test_check(ret64 == -EACCES, "kh port manage_only wait denied");

            ret64 = sys_kairos_port_bind((uint64_t)port_manage_from_fd_h,
                                         (uint64_t)h1, 0x56, KPORT_BIND_READABLE,
                                         0, 0);
            test_check(ret64 == 0, "kh port manage_only bind allowed");
        }
    }

    ret64 = sys_kairos_handle_from_fd((uint64_t)port_fd, (uint64_t)u_hout, 0, 0, 0,
                                      0);
    test_check(ret64 == 0, "kh handle_from_fd port");
    if (ret64 == 0) {
        ret = copy_from_user(&port_from_fd_h, u_hout, sizeof(port_from_fd_h));
        test_check(ret == 0, "kh read port handle from fd");
        if (ret < 0)
            goto out;
    }

    ret64 = sys_kairos_handle_from_fd((uint64_t)port_fd, (uint64_t)u_hout,
                                      (uint64_t)KRIGHT_READ, 0, 0, 0);
    test_check(ret64 == -EACCES, "kh handle_from_fd port reject read mask");

    if (port_from_fd_h >= 0) {
        ret64 = sys_kairos_port_wait((uint64_t)port_from_fd_h, (uint64_t)u_pkt, 0,
                                     KPORT_WAIT_NONBLOCK, 0, 0);
        test_check(ret64 == -EAGAIN, "kh handle_from_fd port wait");

        ret64 = sys_kairos_port_bind((uint64_t)port_from_fd_h, (uint64_t)h1, 0x55,
                                     KPORT_BIND_READABLE | KPORT_BIND_PEER_CLOSED,
                                     0, 0);
        test_check(ret64 == 0, "kh handle_from_fd port manage");

        struct kairos_channel_msg_user xfer_port_msg = {
            .bytes = 0,
            .handles = (uint64_t)(uintptr_t)u_send_handles,
            .num_bytes = 0,
            .num_handles = 1,
        };
        ret = copy_to_user(u_send_handles, &port_from_fd_h, sizeof(port_from_fd_h));
        test_check(ret == 0, "kh copy port handle for transfer");
        ret = copy_to_user(u_send_msg, &xfer_port_msg, sizeof(xfer_port_msg));
        test_check(ret == 0, "kh copy port transfer msg");
        if (ret < 0)
            goto out;

        ret64 = sys_kairos_channel_send((uint64_t)h0, (uint64_t)u_send_msg, 0, 0, 0,
                                        0);
        test_check(ret64 == -EACCES, "kh handle_from_fd port transfer denied");
    }

    ret64 = sys_kairos_fd_from_handle((uint64_t)port, (uint64_t)u_hout,
                                      (uint64_t)O_NONBLOCK, 0, 0, 0);
    test_check(ret64 == 0, "kh fd_from_handle port nonblock");
    if (ret64 < 0)
        goto out;
    ret = copy_from_user(&port_nb_fd, u_hout, sizeof(port_nb_fd));
    test_check(ret == 0, "kh read port nonblock fd");
    if (ret < 0)
        goto out;

    ret64 = sys_read((uint64_t)port_nb_fd, (uint64_t)u_pkt, sizeof(*u_pkt), 0, 0,
                     0);
    test_check(ret64 == -EAGAIN, "kh portfd nonblock read empty");

    struct pollfd pfd = {
        .fd = port_fd,
        .events = POLLIN,
        .revents = 0,
    };
    ret = copy_to_user(u_pollfd, &pfd, sizeof(pfd));
    test_check(ret == 0, "kh copy pollfd idle");
    if (ret < 0)
        goto out;
    ret64 = sys_poll((uint64_t)u_pollfd, 1, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh portfd poll idle");
    if (ret64 < 0)
        goto out;

    ret64 =
        sys_kairos_fd_from_handle((uint64_t)h1, (uint64_t)u_hout, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh fd_from_handle channel");
    if (ret64 < 0)
        goto out;
    ret = copy_from_user(&ch_fd, u_hout, sizeof(ch_fd));
    test_check(ret == 0, "kh read channel fd");
    if (ret < 0)
        goto out;

    ret64 = sys_kairos_handle_duplicate((uint64_t)h1,
                                        KRIGHT_READ | KRIGHT_DUPLICATE,
                                        (uint64_t)u_hout, 0, 0, 0);
    test_check(ret64 == 0, "kh duplicate channel read_only");
    if (ret64 == 0) {
        ret = copy_from_user(&ch_ro_h, u_hout, sizeof(ch_ro_h));
        test_check(ret == 0, "kh read channel read_only handle");
        if (ret < 0)
            goto out;
    }

    if (ch_ro_h >= 0) {
        ret64 = sys_kairos_fd_from_handle((uint64_t)ch_ro_h, (uint64_t)u_hout, 0, 0,
                                          0, 0);
        test_check(ret64 == 0, "kh fd_from_handle channel read_only");
        if (ret64 == 0) {
            ret = copy_from_user(&ch_ro_fd, u_hout, sizeof(ch_ro_fd));
            test_check(ret == 0, "kh read channel read_only fd");
            if (ret < 0)
                goto out;
        }
    }

    if (ch_ro_fd >= 0) {
        struct pollfd ropfd = {
            .fd = ch_ro_fd,
            .events = POLLOUT,
            .revents = 0,
        };
        ret = copy_to_user(u_pollfd, &ropfd, sizeof(ropfd));
        test_check(ret == 0, "kh copy read_only channelfd pollout");
        if (ret < 0)
            goto out;
        ret64 = sys_poll((uint64_t)u_pollfd, 1, 0, 0, 0, 0);
        test_check(ret64 == 0, "kh read_only channelfd suppress pollout");

        ret = copy_to_user(u_send_bytes, "RO", 2);
        test_check(ret == 0, "kh copy read_only channelfd write bytes");
        if (ret < 0)
            goto out;
        ret64 = sys_write((uint64_t)ch_ro_fd, (uint64_t)u_send_bytes, 2, 0, 0, 0);
        test_check(ret64 == -EBADF, "kh read_only channelfd write denied");
    }

    ret64 = sys_kairos_handle_duplicate((uint64_t)h1,
                                        KRIGHT_WRITE | KRIGHT_DUPLICATE,
                                        (uint64_t)u_hout, 0, 0, 0);
    test_check(ret64 == 0, "kh duplicate channel write_only");
    if (ret64 == 0) {
        ret = copy_from_user(&ch_wo_h, u_hout, sizeof(ch_wo_h));
        test_check(ret == 0, "kh read channel write_only handle");
        if (ret < 0)
            goto out;
    }

    if (ch_wo_h >= 0) {
        ret64 = sys_kairos_fd_from_handle((uint64_t)ch_wo_h, (uint64_t)u_hout, 0, 0,
                                          0, 0);
        test_check(ret64 == 0, "kh fd_from_handle channel write_only");
        if (ret64 == 0) {
            ret = copy_from_user(&ch_wo_fd, u_hout, sizeof(ch_wo_fd));
            test_check(ret == 0, "kh read channel write_only fd");
            if (ret < 0)
                goto out;
        }
    }

    if (ch_wo_fd >= 0) {
        struct kairos_channel_msg_user wo_send = {
            .bytes = (uint64_t)(uintptr_t)u_send_bytes,
            .handles = 0,
            .num_bytes = 2,
            .num_handles = 0,
        };
        ret = copy_to_user(u_send_bytes, "WO", 2);
        test_check(ret == 0, "kh copy write_only channelfd send bytes");
        ret = copy_to_user(u_send_msg, &wo_send, sizeof(wo_send));
        test_check(ret == 0, "kh copy write_only channelfd send msg");
        if (ret < 0)
            goto out;

        ret64 = sys_kairos_channel_send((uint64_t)h0, (uint64_t)u_send_msg, 0, 0, 0,
                                        0);
        test_check(ret64 == 0, "kh channel_send for write_only channelfd poll");
        if (ret64 < 0)
            goto out;

        struct pollfd wopfd = {
            .fd = ch_wo_fd,
            .events = POLLIN,
            .revents = 0,
        };
        ret = copy_to_user(u_pollfd, &wopfd, sizeof(wopfd));
        test_check(ret == 0, "kh copy write_only channelfd pollin");
        if (ret < 0)
            goto out;
        ret64 = sys_poll((uint64_t)u_pollfd, 1, 0, 0, 0, 0);
        test_check(ret64 == 0, "kh write_only channelfd suppress pollin");

        ret64 = sys_read((uint64_t)ch_wo_fd, (uint64_t)u_recv_bytes, 8, 0, 0, 0);
        test_check(ret64 == -EBADF, "kh write_only channelfd read denied");

        struct kairos_channel_msg_user wo_recv = {
            .bytes = (uint64_t)(uintptr_t)u_recv_bytes,
            .handles = 0,
            .num_bytes = 8,
            .num_handles = 0,
        };
        ret = copy_to_user(u_recv_msg, &wo_recv, sizeof(wo_recv));
        test_check(ret == 0, "kh copy write_only channelfd recv msg");
        if (ret < 0)
            goto out;
        ret64 = sys_kairos_channel_recv((uint64_t)h1, (uint64_t)u_recv_msg, 0, 0, 0,
                                        0);
        test_check(ret64 == 0, "kh recv write_only channelfd queued payload");
        if (ret64 == 0) {
            struct kairos_channel_msg_user got = {0};
            char got_bytes[2] = {0};
            ret = copy_from_user(&got, u_recv_msg, sizeof(got));
            test_check(ret == 0, "kh read write_only channelfd recv meta");
            ret = copy_from_user(got_bytes, u_recv_bytes, sizeof(got_bytes));
            test_check(ret == 0, "kh read write_only channelfd recv bytes");
            if (ret == 0) {
                test_check(got.num_bytes == 2,
                           "kh write_only channelfd recv num_bytes");
                test_check(memcmp(got_bytes, "WO", 2) == 0,
                           "kh write_only channelfd payload");
            }
        }
    }

    ret64 = sys_kairos_handle_from_fd((uint64_t)ch_fd, (uint64_t)u_hout, 0, 0, 0,
                                      0);
    test_check(ret64 == 0, "kh handle_from_fd channel");
    if (ret64 == 0) {
        ret = copy_from_user(&ch_from_fd_h, u_hout, sizeof(ch_from_fd_h));
        test_check(ret == 0, "kh read channel handle from fd");
        if (ret < 0)
            goto out;
    }

    ret64 = sys_kairos_handle_from_fd((uint64_t)ch_fd, (uint64_t)u_hout,
                                      (uint64_t)KRIGHT_WAIT, 0, 0, 0);
    test_check(ret64 == -EACCES, "kh handle_from_fd channel reject wait mask");

    if (ch_from_fd_h >= 0) {
        struct kairos_channel_msg_user from_fd_send = {
            .bytes = (uint64_t)(uintptr_t)u_send_bytes,
            .handles = 0,
            .num_bytes = 2,
            .num_handles = 0,
        };
        ret = copy_to_user(u_send_bytes, "HF", 2);
        test_check(ret == 0, "kh copy channel handle-from-fd bytes");
        ret = copy_to_user(u_send_msg, &from_fd_send, sizeof(from_fd_send));
        test_check(ret == 0, "kh copy channel handle-from-fd send msg");
        if (ret < 0)
            goto out;

        ret64 = sys_kairos_channel_send((uint64_t)ch_from_fd_h, (uint64_t)u_send_msg,
                                        0, 0, 0, 0);
        test_check(ret64 == 0, "kh handle_from_fd channel send");
        if (ret64 < 0)
            goto out;

        struct kairos_channel_msg_user from_fd_recv = {
            .bytes = (uint64_t)(uintptr_t)u_recv_bytes,
            .handles = 0,
            .num_bytes = 8,
            .num_handles = 0,
        };
        ret = copy_to_user(u_recv_msg, &from_fd_recv, sizeof(from_fd_recv));
        test_check(ret == 0, "kh copy channel handle-from-fd recv msg");
        if (ret < 0)
            goto out;

        ret64 =
            sys_kairos_channel_recv((uint64_t)h0, (uint64_t)u_recv_msg, 0, 0, 0, 0);
        test_check(ret64 == 0, "kh handle_from_fd channel recv");
        if (ret64 == 0) {
            struct kairos_channel_msg_user got = {0};
            char got_bytes[2] = {0};
            ret = copy_from_user(&got, u_recv_msg, sizeof(got));
            test_check(ret == 0, "kh read channel handle-from-fd recv meta");
            ret = copy_from_user(got_bytes, u_recv_bytes, sizeof(got_bytes));
            test_check(ret == 0, "kh read channel handle-from-fd recv bytes");
            if (ret == 0) {
                test_check(got.num_bytes == 2,
                           "kh channel handle-from-fd recv num_bytes");
                test_check(memcmp(got_bytes, "HF", 2) == 0,
                           "kh channel handle-from-fd payload");
            }
        }
    }

    ret64 = sys_kairos_fd_from_handle((uint64_t)h1, (uint64_t)u_hout,
                                      (uint64_t)O_NONBLOCK, 0, 0, 0);
    test_check(ret64 == 0, "kh fd_from_handle channel nonblock");
    if (ret64 < 0)
        goto out;
    ret = copy_from_user(&ch_nb_fd, u_hout, sizeof(ch_nb_fd));
    test_check(ret == 0, "kh read channel nonblock fd");
    if (ret < 0)
        goto out;

    ret64 = sys_read((uint64_t)ch_nb_fd, (uint64_t)u_recv_bytes, 8, 0, 0, 0);
    test_check(ret64 == -EAGAIN, "kh channelfd nonblock read empty");

    pfd.fd = ch_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    ret = copy_to_user(u_pollfd, &pfd, sizeof(pfd));
    test_check(ret == 0, "kh copy ch pollfd idle");
    if (ret < 0)
        goto out;
    ret64 = sys_poll((uint64_t)u_pollfd, 1, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh channelfd poll idle");
    if (ret64 < 0)
        goto out;

    struct kairos_channel_msg_user ch_send_msg = {
        .bytes = (uint64_t)(uintptr_t)u_send_bytes,
        .handles = 0,
        .num_bytes = 2,
        .num_handles = 0,
    };
    ret = copy_to_user(u_send_bytes, "FD", 2);
    test_check(ret == 0, "kh copy channel fd send bytes");
    ret = copy_to_user(u_send_msg, &ch_send_msg, sizeof(ch_send_msg));
    test_check(ret == 0, "kh copy channel fd send msg");
    if (ret < 0)
        goto out;
    ret64 = sys_kairos_channel_send((uint64_t)h0, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh channel_send for channelfd");
    if (ret64 < 0)
        goto out;

    pfd.fd = ch_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    ret = copy_to_user(u_pollfd, &pfd, sizeof(pfd));
    test_check(ret == 0, "kh copy ch pollfd readable");
    if (ret < 0)
        goto out;
    ret64 = sys_poll((uint64_t)u_pollfd, 1, 0, 0, 0, 0);
    test_check(ret64 == 1, "kh channelfd poll readable");
    if (ret64 == 1) {
        ret = copy_from_user(&pfd, u_pollfd, sizeof(pfd));
        test_check(ret == 0, "kh read ch pollfd readable");
        if (ret == 0)
            test_check((pfd.revents & POLLIN) != 0, "kh channelfd pollin");
    }

    ret64 = sys_read((uint64_t)ch_fd, (uint64_t)u_recv_bytes, 8, 0, 0, 0);
    test_check(ret64 == 2, "kh channelfd read");
    if (ret64 == 2) {
        char got[2] = {0};
        ret = copy_from_user(got, u_recv_bytes, sizeof(got));
        test_check(ret == 0, "kh read channelfd bytes");
        if (ret == 0)
            test_check(memcmp(got, "FD", 2) == 0, "kh channelfd payload");
    }

    ret64 =
        sys_kairos_handle_duplicate((uint64_t)h2b, 0, (uint64_t)u_hout, 0, 0, 0);
    test_check(ret64 == 0, "kh duplicate for channelfd drop");
    if (ret64 == 0) {
        ret = copy_from_user(&drop_h, u_hout, sizeof(drop_h));
        test_check(ret == 0, "kh read duplicate for channelfd drop");
    }

    if (drop_h >= 0) {
        struct kairos_channel_msg_user ch_drop_msg = {
            .bytes = (uint64_t)(uintptr_t)u_send_bytes,
            .handles = (uint64_t)(uintptr_t)u_send_handles,
            .num_bytes = 2,
            .num_handles = 1,
        };
        ret = copy_to_user(u_send_bytes, "HC", 2);
        test_check(ret == 0, "kh copy channelfd drop bytes");
        ret = copy_to_user(u_send_handles, &drop_h, sizeof(drop_h));
        test_check(ret == 0, "kh copy channelfd drop handle");
        ret = copy_to_user(u_send_msg, &ch_drop_msg, sizeof(ch_drop_msg));
        test_check(ret == 0, "kh copy channelfd drop msg");
        if (ret < 0)
            goto out;

        ret64 = sys_kairos_channel_send((uint64_t)h0, (uint64_t)u_send_msg, 0, 0, 0,
                                        0);
        test_check(ret64 == 0, "kh send channelfd drop msg");
        if (ret64 < 0)
            goto out;

        ret64 = sys_kairos_handle_close((uint64_t)drop_h, 0, 0, 0, 0, 0);
        test_check(ret64 == -EBADF, "kh channelfd drop moved source");
        drop_h = -1;

        ret64 = sys_read((uint64_t)ch_fd, (uint64_t)u_recv_bytes, 8, 0, 0, 0);
        test_check(ret64 == 2, "kh channelfd read with dropped handles");
        if (ret64 == 2) {
            char got[2] = {0};
            ret = copy_from_user(got, u_recv_bytes, sizeof(got));
            test_check(ret == 0, "kh read channelfd dropped bytes");
            if (ret == 0) {
                test_check(memcmp(got, "HC", 2) == 0,
                           "kh channelfd dropped payload");
            }
        }
    }

    ret = copy_to_user(u_send_bytes, "WR", 2);
    test_check(ret == 0, "kh copy channelfd write bytes");
    if (ret < 0)
        goto out;
    ret64 = sys_write((uint64_t)ch_fd, (uint64_t)u_send_bytes, 2, 0, 0, 0);
    test_check(ret64 == 2, "kh channelfd write");
    if (ret64 < 0)
        goto out;

    struct kairos_channel_msg_user ch_recv_msg = {
        .bytes = (uint64_t)(uintptr_t)u_recv_bytes,
        .handles = 0,
        .num_bytes = 8,
        .num_handles = 0,
    };
    ret = copy_to_user(u_recv_msg, &ch_recv_msg, sizeof(ch_recv_msg));
    test_check(ret == 0, "kh copy recv msg from channelfd write");
    if (ret < 0)
        goto out;
    ret64 = sys_kairos_channel_recv((uint64_t)h0, (uint64_t)u_recv_msg, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh recv channelfd write payload");
    if (ret64 == 0) {
        struct kairos_channel_msg_user got = {0};
        char got_bytes[2] = {0};
        ret = copy_from_user(&got, u_recv_msg, sizeof(got));
        test_check(ret == 0, "kh read recv msg from channelfd");
        ret = copy_from_user(got_bytes, u_recv_bytes, sizeof(got_bytes));
        test_check(ret == 0, "kh read recv bytes from channelfd");
        if (ret == 0) {
            test_check(got.num_bytes == 2, "kh recv num_bytes from channelfd");
            test_check(memcmp(got_bytes, "WR", 2) == 0,
                       "kh recv payload from channelfd");
        }
    }

    {
        struct process *self = proc_current();
        struct kobj *rv_send_obj = NULL;
        struct kobj *rv_recv_obj = NULL;
        int krc = khandle_get(self, h0, KRIGHT_WRITE, &rv_send_obj, NULL);
        test_check(krc == 0, "kh rendezvous get send");
        if (krc < 0)
            goto out;
        krc = khandle_get(self, h1, KRIGHT_READ, &rv_recv_obj, NULL);
        test_check(krc == 0, "kh rendezvous get recv");
        if (krc < 0) {
            kobj_put(rv_send_obj);
            goto out;
        }

        struct kh_rendezvous_ctx rv_ctx;
        memset(&rv_ctx, 0, sizeof(rv_ctx));
        rv_ctx.recv_obj = rv_recv_obj;
        struct process *rv_worker =
            kthread_create_joinable(kh_rendezvous_recv_worker, &rv_ctx, "khrv");
        test_check(rv_worker != NULL, "kh rendezvous worker create");
        if (!rv_worker) {
            kobj_put(rv_recv_obj);
            kobj_put(rv_send_obj);
            goto out;
        }
        pid_t rv_pid = rv_worker->pid;
        sched_enqueue(rv_worker);

        for (int spins = 0; spins < 5000 && rv_ctx.armed == 0; spins++)
            proc_yield();
        test_check(rv_ctx.armed != 0, "kh rendezvous worker armed");

        const char rv_payload[] = {'R', 'V', 'Z'};
        krc = kchannel_send(rv_send_obj, rv_payload, sizeof(rv_payload), NULL, 0,
                            KCHANNEL_OPT_RENDEZVOUS);
        test_check(krc == 0, "kh rendezvous send");

        int status = 0;
        pid_t wp = proc_wait(rv_pid, &status, 0);
        test_check(wp == rv_pid, "kh rendezvous worker reaped");
        test_check(rv_ctx.rc == 0, "kh rendezvous recv rc");
        test_check(rv_ctx.got_bytes == sizeof(rv_payload),
                   "kh rendezvous recv bytes");
        test_check(rv_ctx.got_handles == 0, "kh rendezvous recv handles");
        test_check(rv_ctx.trunc == false, "kh rendezvous recv trunc");
        test_check(memcmp(rv_ctx.payload, rv_payload, sizeof(rv_payload)) == 0,
                   "kh rendezvous payload");

        kobj_put(rv_recv_obj);
        kobj_put(rv_send_obj);
    }

    {
        struct kairos_channel_msg_user rv_sys_send = {
            .bytes = (uint64_t)(uintptr_t)u_send_bytes,
            .handles = 0,
            .num_bytes = 3,
            .num_handles = 0,
        };
        ret = copy_to_user(u_send_bytes, "RSY", 3);
        test_check(ret == 0, "kh rendezvous syscall send bytes");
        ret = copy_to_user(u_send_msg, &rv_sys_send, sizeof(rv_sys_send));
        test_check(ret == 0, "kh rendezvous syscall send msg");
        if (ret < 0)
            goto out;

        ret64 = sys_kairos_channel_send((uint64_t)h0, (uint64_t)u_send_msg,
                                        KCHANNEL_OPT_RENDEZVOUS, 0, 0, 0);
        test_check(ret64 == 0, "kh rendezvous syscall send");
        if (ret64 < 0)
            goto out;

        struct kairos_channel_msg_user rv_sys_recv = {
            .bytes = (uint64_t)(uintptr_t)u_recv_bytes,
            .handles = 0,
            .num_bytes = 8,
            .num_handles = 0,
        };
        ret = copy_to_user(u_recv_msg, &rv_sys_recv, sizeof(rv_sys_recv));
        test_check(ret == 0, "kh rendezvous syscall recv msg");
        if (ret < 0)
            goto out;

        ret64 = sys_kairos_channel_recv((uint64_t)h1, (uint64_t)u_recv_msg,
                                        KCHANNEL_OPT_RENDEZVOUS, 0, 0, 0);
        test_check(ret64 == 0, "kh rendezvous syscall recv");
        if (ret64 == 0) {
            struct kairos_channel_msg_user got = {0};
            char got_bytes[3] = {0};
            ret = copy_from_user(&got, u_recv_msg, sizeof(got));
            test_check(ret == 0, "kh rendezvous syscall recv meta");
            ret = copy_from_user(got_bytes, u_recv_bytes, sizeof(got_bytes));
            test_check(ret == 0, "kh rendezvous syscall recv bytes");
            if (ret == 0) {
                test_check(got.num_bytes == 3,
                           "kh rendezvous syscall recv num_bytes");
                test_check(memcmp(got_bytes, "RSY", 3) == 0,
                           "kh rendezvous syscall payload");
            }
        }
    }

    struct kairos_channel_msg_user send_msg = {
        .bytes = (uint64_t)(uintptr_t)u_send_bytes,
        .handles = (uint64_t)(uintptr_t)u_send_handles,
        .num_bytes = 4,
        .num_handles = 1,
    };
    ret = copy_to_user(u_send_bytes, "PING", 4);
    test_check(ret == 0, "kh copy send bytes");
    ret = copy_to_user(u_send_handles, &h2b, sizeof(h2b));
    test_check(ret == 0, "kh copy send handle");
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "kh copy send msg");
    if (ret < 0)
        goto out;

    ret64 = sys_kairos_channel_send((uint64_t)h0, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh channel_send transfer");
    if (ret64 < 0)
        goto out;

    ret64 = sys_kairos_handle_close((uint64_t)h2b, 0, 0, 0, 0, 0);
    test_check(ret64 == -EBADF, "kh transfer moved source handle");
    h2b = -1;

    pfd.fd = port_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    ret = copy_to_user(u_pollfd, &pfd, sizeof(pfd));
    test_check(ret == 0, "kh copy pollfd readable");
    if (ret < 0)
        goto out;
    ret64 = sys_poll((uint64_t)u_pollfd, 1, 0, 0, 0, 0);
    test_check(ret64 == 1, "kh portfd poll readable");
    if (ret64 == 1) {
        ret = copy_from_user(&pfd, u_pollfd, sizeof(pfd));
        test_check(ret == 0, "kh read pollfd readable");
        if (ret == 0) {
            test_check((pfd.revents & POLLIN) != 0, "kh portfd pollin");
        }
    }

    ret64 = sys_read((uint64_t)port_fd, (uint64_t)u_pkt, sizeof(*u_pkt), 0, 0, 0);
    test_check(ret64 == (int64_t)sizeof(*u_pkt), "kh portfd read packet");
    if (ret64 == (int64_t)sizeof(*u_pkt)) {
        struct kairos_port_packet_user pkt = {0};
        ret = copy_from_user(&pkt, u_pkt, sizeof(pkt));
        test_check(ret == 0, "kh read pkt readable");
        if (ret == 0) {
            test_check(pkt.key == 0x55, "kh pkt key readable");
            test_check((pkt.observed & KPORT_BIND_READABLE) != 0,
                       "kh pkt readable signal");
        }
    }

    struct kairos_channel_msg_user recv_msg = {
        .bytes = (uint64_t)(uintptr_t)u_recv_bytes,
        .handles = (uint64_t)(uintptr_t)u_recv_handles,
        .num_bytes = 16,
        .num_handles = 4,
    };
    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "kh copy recv msg");
    if (ret < 0)
        goto out;

    ret64 = sys_kairos_channel_recv((uint64_t)h1, (uint64_t)u_recv_msg, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh channel_recv transfer");
    if (ret64 == 0) {
        struct kairos_channel_msg_user got = {0};
        char got_bytes[4] = {0};
        ret = copy_from_user(&got, u_recv_msg, sizeof(got));
        test_check(ret == 0, "kh read recv msg");
        ret = copy_from_user(got_bytes, u_recv_bytes, 4);
        test_check(ret == 0, "kh read recv bytes");
        ret = copy_from_user(&recv_h, u_recv_handles, sizeof(recv_h));
        test_check(ret == 0, "kh read recv handle");
        if (ret == 0) {
            test_check(got.num_bytes == 4, "kh recv num_bytes");
            test_check(got.num_handles == 1, "kh recv num_handles");
            test_check(memcmp(got_bytes, "PING", 4) == 0, "kh recv payload");
        }
    }

    if (recv_h >= 0) {
        send_msg.bytes = (uint64_t)(uintptr_t)u_send_bytes;
        send_msg.handles = 0;
        send_msg.num_bytes = 1;
        send_msg.num_handles = 0;
        ret = copy_to_user(u_send_bytes, "X", 1);
        test_check(ret == 0, "kh copy send x");
        ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
        test_check(ret == 0, "kh copy send x msg");
        if (ret == 0) {
            ret64 = sys_kairos_channel_send((uint64_t)recv_h, (uint64_t)u_send_msg, 0,
                                            0, 0, 0);
            test_check(ret64 == 0, "kh send received handle");
        }

        recv_msg.bytes = (uint64_t)(uintptr_t)u_recv_bytes;
        recv_msg.handles = (uint64_t)(uintptr_t)u_recv_handles;
        recv_msg.num_bytes = 4;
        recv_msg.num_handles = 1;
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "kh copy recv via peer");
        if (ret == 0) {
            ret64 = sys_kairos_channel_recv((uint64_t)h2a, (uint64_t)u_recv_msg, 0, 0,
                                            0, 0);
            test_check(ret64 == 0, "kh recv via transferred endpoint");
            if (ret64 == 0) {
                char x = 0;
                ret = copy_from_user(&x, u_recv_bytes, 1);
                test_check(ret == 0, "kh read x");
                if (ret == 0)
                    test_check(x == 'X', "kh payload x");
            }
        }
    }

    ret64 = sys_kairos_handle_duplicate((uint64_t)h0, KRIGHT_READ,
                                        (uint64_t)u_hout, 0, 0, 0);
    test_check(ret64 == 0, "kh duplicate read_only");
    if (ret64 == 0) {
        ret = copy_from_user(&dup_h, u_hout, sizeof(dup_h));
        test_check(ret == 0, "kh read dup");
    }

    if (dup_h >= 0) {
        send_msg.bytes = (uint64_t)(uintptr_t)u_send_bytes;
        send_msg.handles = 0;
        send_msg.num_bytes = 1;
        send_msg.num_handles = 0;
        ret = copy_to_user(u_send_bytes, "Z", 1);
        test_check(ret == 0, "kh copy z");
        ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
        test_check(ret == 0, "kh copy z msg");
        if (ret == 0) {
            ret64 = sys_kairos_channel_send((uint64_t)dup_h, (uint64_t)u_send_msg, 0,
                                            0, 0, 0);
            test_check(ret64 == -EACCES, "kh read_only send denied");
        }

        ret64 = sys_kairos_handle_close((uint64_t)dup_h, 0, 0, 0, 0, 0);
        test_check(ret64 == 0, "kh close dup");
        if (ret64 == 0)
            dup_h = -1;
    }

    ret64 = sys_kairos_handle_close((uint64_t)h0, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh close h0");
    if (ret64 == 0)
        h0 = -1;

    if (ch_fd >= 0) {
        pfd.fd = ch_fd;
        pfd.events = POLLIN | POLLHUP;
        pfd.revents = 0;
        ret = copy_to_user(u_pollfd, &pfd, sizeof(pfd));
        test_check(ret == 0, "kh copy ch pollfd peer_closed");
        if (ret == 0) {
            ret64 = sys_poll((uint64_t)u_pollfd, 1, 0, 0, 0, 0);
            test_check(ret64 == 1, "kh channelfd poll peer_closed");
            if (ret64 == 1) {
                ret = copy_from_user(&pfd, u_pollfd, sizeof(pfd));
                test_check(ret == 0, "kh read ch pollfd peer_closed");
                if (ret == 0)
                    test_check((pfd.revents & POLLHUP) != 0,
                               "kh channelfd pollhup");
            }
        }
    }

    ret64 = sys_kairos_port_wait((uint64_t)port, (uint64_t)u_pkt, 500000000ULL, 0,
                                 0, 0);
    test_check(ret64 == 0, "kh port_wait peer_closed");
    if (ret64 == 0) {
        struct kairos_port_packet_user pkt = {0};
        ret = copy_from_user(&pkt, u_pkt, sizeof(pkt));
        test_check(ret == 0, "kh read pkt peer_closed");
        if (ret == 0) {
            test_check(pkt.key == 0x55, "kh pkt key peer_closed");
            test_check((pkt.observed & KPORT_BIND_PEER_CLOSED) != 0,
                       "kh pkt peer_closed signal");
        }
    }

out:
    if (ch_from_fd_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)ch_from_fd_h, 0, 0, 0, 0, 0);
    if (port_manage_from_fd_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)port_manage_from_fd_h, 0, 0, 0, 0,
                                      0);
    if (port_manage_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)port_manage_h, 0, 0, 0, 0, 0);
    if (port_from_fd_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)port_from_fd_h, 0, 0, 0, 0, 0);
    if (port_manage_fd >= 0)
        (void)sys_close((uint64_t)port_manage_fd, 0, 0, 0, 0, 0);
    if (ch_wo_fd >= 0)
        (void)sys_close((uint64_t)ch_wo_fd, 0, 0, 0, 0, 0);
    if (ch_ro_fd >= 0)
        (void)sys_close((uint64_t)ch_ro_fd, 0, 0, 0, 0, 0);
    if (ch_nb_fd >= 0)
        (void)sys_close((uint64_t)ch_nb_fd, 0, 0, 0, 0, 0);
    if (ch_fd >= 0)
        (void)sys_close((uint64_t)ch_fd, 0, 0, 0, 0, 0);
    if (port_nb_fd >= 0)
        (void)sys_close((uint64_t)port_nb_fd, 0, 0, 0, 0, 0);
    if (port_fd >= 0)
        (void)sys_close((uint64_t)port_fd, 0, 0, 0, 0, 0);
    if (dup_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)dup_h, 0, 0, 0, 0, 0);
    if (drop_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)drop_h, 0, 0, 0, 0, 0);
    if (recv_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)recv_h, 0, 0, 0, 0, 0);
    if (ch_wo_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)ch_wo_h, 0, 0, 0, 0, 0);
    if (ch_ro_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)ch_ro_h, 0, 0, 0, 0, 0);
    if (port >= 0)
        (void)sys_kairos_handle_close((uint64_t)port, 0, 0, 0, 0, 0);
    if (h2a >= 0)
        (void)sys_kairos_handle_close((uint64_t)h2a, 0, 0, 0, 0, 0);
    if (h2b >= 0)
        (void)sys_kairos_handle_close((uint64_t)h2b, 0, 0, 0, 0, 0);
    if (h1 >= 0)
        (void)sys_kairos_handle_close((uint64_t)h1, 0, 0, 0, 0, 0);
    if (h0 >= 0)
        (void)sys_kairos_handle_close((uint64_t)h0, 0, 0, 0, 0, 0);
    if (mapped)
        user_map_end(&um);
}

static void test_kairos_channel_port_stress_mpmc(void) {
    struct kh_stress_suite suite;
    atomic_init(&suite.sent, 0);
    atomic_init(&suite.received, 0);
    atomic_init(&suite.acked, 0);
    atomic_init(&suite.producers_done, 0);
    atomic_init(&suite.errors, 0);

    struct kobj *tx_obj = NULL;
    struct kobj *rx_obj = NULL;
    struct kobj *port_obj = NULL;
    struct kobj *ack_tx[KH_STRESS_PRODUCERS] = {0};
    struct kobj *ack_rx[KH_STRESS_PRODUCERS] = {0};

    struct kh_stress_producer_ctx pctx[KH_STRESS_PRODUCERS];
    struct kh_stress_consumer_ctx cctx[KH_STRESS_CONSUMERS];
    struct process *prod_proc[KH_STRESS_PRODUCERS] = {0};
    struct process *cons_proc[KH_STRESS_CONSUMERS] = {0};
    uint32_t started_prod = 0;
    uint32_t started_cons = 0;

    memset(pctx, 0, sizeof(pctx));
    memset(cctx, 0, sizeof(cctx));

    int rc = kchannel_create_pair(&tx_obj, &rx_obj);
    test_check(rc == 0, "kh stress create main pair");
    if (rc < 0)
        goto out;

    rc = kport_create(&port_obj);
    test_check(rc == 0, "kh stress create port");
    if (rc < 0)
        goto out;

    rc = kport_bind_channel(port_obj, rx_obj, 0xCAFE,
                            KPORT_BIND_READABLE | KPORT_BIND_PEER_CLOSED);
    test_check(rc == 0, "kh stress bind port");
    if (rc < 0)
        goto out;

    for (uint32_t i = 0; i < KH_STRESS_PRODUCERS; i++) {
        rc = kchannel_create_pair(&ack_rx[i], &ack_tx[i]);
        test_check(rc == 0, "kh stress create ack pair");
        if (rc < 0)
            goto out;
    }

    for (uint32_t i = 0; i < KH_STRESS_CONSUMERS; i++) {
        cons_proc[i] =
            kthread_create_joinable(kh_stress_consumer_worker, &cctx[i], "khcsmr");
        test_check(cons_proc[i] != NULL, "kh stress create consumer");
        if (!cons_proc[i])
            goto out;

        cctx[i].suite = &suite;
        cctx[i].h_recv = khandle_alloc(cons_proc[i], rx_obj, KRIGHT_CHANNEL_DEFAULT);
        cctx[i].h_port = khandle_alloc(cons_proc[i], port_obj, KRIGHT_PORT_DEFAULT);
        if (cctx[i].h_recv < 0 || cctx[i].h_port < 0) {
            test_check(false, "kh stress consumer handle alloc");
            goto out;
        }
        sched_enqueue(cons_proc[i]);
        started_cons++;
    }

    for (uint32_t i = 0; i < KH_STRESS_PRODUCERS; i++) {
        prod_proc[i] =
            kthread_create_joinable(kh_stress_producer_worker, &pctx[i], "khprod");
        test_check(prod_proc[i] != NULL, "kh stress create producer");
        if (!prod_proc[i])
            goto out;

        pctx[i].suite = &suite;
        pctx[i].producer_id = i;
        pctx[i].h_send = khandle_alloc(prod_proc[i], tx_obj, KRIGHT_CHANNEL_DEFAULT);
        pctx[i].h_ack_send =
            khandle_alloc(prod_proc[i], ack_tx[i], KRIGHT_CHANNEL_DEFAULT);
        pctx[i].h_ack_recv =
            khandle_alloc(prod_proc[i], ack_rx[i], KRIGHT_CHANNEL_DEFAULT);
        if (pctx[i].h_send < 0 || pctx[i].h_ack_send < 0 || pctx[i].h_ack_recv < 0) {
            test_check(false, "kh stress producer handle alloc");
            goto out;
        }
        sched_enqueue(prod_proc[i]);
        started_prod++;
    }

    for (uint32_t i = 0; i < KH_STRESS_PRODUCERS; i++) {
        bool done = kh_wait_pid_bounded(prod_proc[i]->pid, KH_STRESS_RUN_TIMEOUT_NS);
        test_check(done, "kh stress producer reaped");
        prod_proc[i] = NULL;
    }

    if (tx_obj) {
        kobj_put(tx_obj);
        tx_obj = NULL;
    }

    for (uint32_t i = 0; i < KH_STRESS_CONSUMERS; i++) {
        bool done = kh_wait_pid_bounded(cons_proc[i]->pid, KH_STRESS_RUN_TIMEOUT_NS);
        test_check(done, "kh stress consumer reaped");
        cons_proc[i] = NULL;
    }

    test_check(atomic_read(&suite.errors) == 0, "kh stress no internal errors");
    test_check(atomic_read(&suite.sent) == KH_STRESS_TOTAL_MSGS, "kh stress sent");
    test_check(atomic_read(&suite.received) == KH_STRESS_TOTAL_MSGS,
               "kh stress received");
    test_check(atomic_read(&suite.acked) == KH_STRESS_TOTAL_MSGS, "kh stress acked");

out:
    for (uint32_t i = 0; i < started_prod; i++) {
        if (prod_proc[i])
            (void)kh_wait_pid_bounded(prod_proc[i]->pid, KH_STRESS_RUN_TIMEOUT_NS);
    }
    for (uint32_t i = 0; i < started_cons; i++) {
        if (cons_proc[i])
            (void)kh_wait_pid_bounded(cons_proc[i]->pid, KH_STRESS_RUN_TIMEOUT_NS);
    }
    if (tx_obj)
        kobj_put(tx_obj);
    if (rx_obj)
        kobj_put(rx_obj);
    if (port_obj)
        kobj_put(port_obj);
    for (uint32_t i = 0; i < KH_STRESS_PRODUCERS; i++) {
        if (ack_tx[i])
            kobj_put(ack_tx[i]);
        if (ack_rx[i])
            kobj_put(ack_rx[i]);
    }
}

static void test_kairos_file_handle_bridge(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int32_t pfds[2] = {-1, -1};
    int32_t ch0 = -1;
    int32_t ch1 = -1;
    int32_t tx_h = -1;
    int32_t rx_h = -1;
    int32_t bridged_fd = -1;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "kh_file_bridge user_map");
    if (rc < 0)
        return;
    mapped = true;

    int32_t *u_pipefds = (int32_t *)user_map_ptr(&um, 0x000);
    int32_t *u_ch0 = (int32_t *)user_map_ptr(&um, 0x020);
    int32_t *u_ch1 = (int32_t *)user_map_ptr(&um, 0x028);
    int32_t *u_scalar = (int32_t *)user_map_ptr(&um, 0x030);
    int32_t *u_send_handles = (int32_t *)user_map_ptr(&um, 0x040);
    int32_t *u_recv_handles = (int32_t *)user_map_ptr(&um, 0x048);
    struct kairos_channel_msg_user *u_send_msg =
        (struct kairos_channel_msg_user *)user_map_ptr(&um, 0x080);
    struct kairos_channel_msg_user *u_recv_msg =
        (struct kairos_channel_msg_user *)user_map_ptr(&um, 0x0C0);
    char *u_buf = (char *)user_map_ptr(&um, 0x180);
    test_check(u_pipefds && u_ch0 && u_ch1 && u_scalar && u_send_handles &&
                   u_recv_handles && u_send_msg && u_recv_msg && u_buf,
               "kh_file_bridge user_ptr");
    if (!u_pipefds || !u_ch0 || !u_ch1 || !u_scalar || !u_send_handles ||
        !u_recv_handles || !u_send_msg || !u_recv_msg || !u_buf)
        goto out;

    int64_t ret64 = sys_pipe2((uint64_t)u_pipefds, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh_file_bridge pipe2");
    if (ret64 < 0)
        goto out;

    rc = copy_from_user(pfds, u_pipefds, sizeof(pfds));
    test_check(rc == 0, "kh_file_bridge read pipe fds");
    if (rc < 0)
        goto out;

    ret64 = sys_kairos_channel_create((uint64_t)u_ch0, (uint64_t)u_ch1, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh_file_bridge channel_create");
    if (ret64 < 0)
        goto out;

    rc = copy_from_user(&ch0, u_ch0, sizeof(ch0));
    test_check(rc == 0, "kh_file_bridge read ch0");
    rc = copy_from_user(&ch1, u_ch1, sizeof(ch1));
    test_check(rc == 0, "kh_file_bridge read ch1");
    if (rc < 0)
        goto out;

    ret64 = sys_kairos_handle_from_fd((uint64_t)pfds[1], (uint64_t)u_scalar, 0, 0, 0,
                                      0);
    test_check(ret64 == 0, "kh_file_bridge handle_from_fd");
    if (ret64 < 0)
        goto out;

    rc = copy_from_user(&tx_h, u_scalar, sizeof(tx_h));
    test_check(rc == 0, "kh_file_bridge read tx_h");
    if (rc < 0)
        goto out;

    struct kairos_channel_msg_user send_msg = {
        .bytes = 0,
        .handles = (uint64_t)(uintptr_t)u_send_handles,
        .num_bytes = 0,
        .num_handles = 1,
    };
    rc = copy_to_user(u_send_handles, &tx_h, sizeof(tx_h));
    test_check(rc == 0, "kh_file_bridge copy tx_h");
    rc = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(rc == 0, "kh_file_bridge copy send msg");
    if (rc < 0)
        goto out;

    ret64 = sys_kairos_channel_send((uint64_t)ch0, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh_file_bridge send handle");
    if (ret64 < 0)
        goto out;

    ret64 = sys_kairos_handle_close((uint64_t)tx_h, 0, 0, 0, 0, 0);
    test_check(ret64 == -EBADF, "kh_file_bridge handle moved");
    tx_h = -1;

    struct kairos_channel_msg_user recv_msg = {
        .bytes = 0,
        .handles = (uint64_t)(uintptr_t)u_recv_handles,
        .num_bytes = 0,
        .num_handles = 1,
    };
    rc = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(rc == 0, "kh_file_bridge copy recv msg");
    if (rc < 0)
        goto out;

    ret64 = sys_kairos_channel_recv((uint64_t)ch1, (uint64_t)u_recv_msg, 0, 0, 0, 0);
    test_check(ret64 == 0, "kh_file_bridge recv handle");
    if (ret64 < 0)
        goto out;

    rc = copy_from_user(&rx_h, u_recv_handles, sizeof(rx_h));
    test_check(rc == 0, "kh_file_bridge read rx_h");
    if (rc < 0)
        goto out;

    ret64 = sys_kairos_fd_from_handle((uint64_t)rx_h, (uint64_t)u_scalar, 0, 0, 0,
                                      0);
    test_check(ret64 == 0, "kh_file_bridge fd_from_handle");
    if (ret64 < 0)
        goto out;

    ret64 = sys_kairos_fd_from_handle((uint64_t)rx_h, (uint64_t)u_scalar,
                                      (uint64_t)O_NONBLOCK, 0, 0, 0);
    test_check(ret64 == -EINVAL, "kh_file_bridge fd_from_handle nonblock denied");

    rc = copy_from_user(&bridged_fd, u_scalar, sizeof(bridged_fd));
    test_check(rc == 0, "kh_file_bridge read bridged fd");
    if (rc < 0)
        goto out;

    char one = 'H';
    rc = copy_to_user(u_buf, &one, sizeof(one));
    test_check(rc == 0, "kh_file_bridge copy write byte");
    if (rc < 0)
        goto out;

    ret64 = sys_write((uint64_t)bridged_fd, (uint64_t)u_buf, 1, 0, 0, 0);
    test_check(ret64 == 1, "kh_file_bridge write through bridged fd");
    if (ret64 != 1)
        goto out;

    ret64 = sys_read((uint64_t)pfds[0], (uint64_t)u_buf, 1, 0, 0, 0);
    test_check(ret64 == 1, "kh_file_bridge read through pipe");
    if (ret64 == 1) {
        char got = 0;
        rc = copy_from_user(&got, u_buf, sizeof(got));
        test_check(rc == 0, "kh_file_bridge read byte");
        if (rc == 0)
            test_check(got == 'H', "kh_file_bridge payload match");
    }

out:
    if (bridged_fd >= 0)
        (void)sys_close((uint64_t)bridged_fd, 0, 0, 0, 0, 0);
    if (rx_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)rx_h, 0, 0, 0, 0, 0);
    if (tx_h >= 0)
        (void)sys_kairos_handle_close((uint64_t)tx_h, 0, 0, 0, 0, 0);
    if (ch1 >= 0)
        (void)sys_kairos_handle_close((uint64_t)ch1, 0, 0, 0, 0, 0);
    if (ch0 >= 0)
        (void)sys_kairos_handle_close((uint64_t)ch0, 0, 0, 0, 0, 0);
    if (pfds[0] >= 0)
        (void)sys_close((uint64_t)pfds[0], 0, 0, 0, 0, 0);
    if (pfds[1] >= 0)
        (void)sys_close((uint64_t)pfds[1], 0, 0, 0, 0, 0);
    if (mapped)
        user_map_end(&um);
}

static void test_kobj_ops_refcount_history(void) {
    struct kobj *tx_obj = NULL;
    struct kobj *rx_obj = NULL;
    struct kobj *port_obj = NULL;
    int32_t moved_handle = -1;

    int rc = kchannel_create_pair(&tx_obj, &rx_obj);
    test_check(rc == 0, "kobj_ops create pair");
    if (rc < 0)
        return;

    char tx = 'Q';
    size_t wrote = 0;
    rc = kobj_write(tx_obj, &tx, sizeof(tx), &wrote, 0);
    test_check(rc == 0 && wrote == sizeof(tx), "kobj_ops write channel");

    uint32_t revents = 0;
    rc = kobj_poll(rx_obj, POLLIN, &revents);
    test_check(rc == 0 && (revents & POLLIN) != 0, "kobj_ops poll channel");

    char rx = 0;
    size_t read_len = 0;
    rc = kobj_read(rx_obj, &rx, sizeof(rx), &read_len, 0);
    test_check(rc == 0 && read_len == sizeof(rx) && rx == tx,
               "kobj_ops read channel");

    rc = kport_create(&port_obj);
    test_check(rc == 0, "kobj_ops create port");
    if (rc < 0)
        goto out;

    rc = kport_bind_channel(port_obj, rx_obj, 0x1234, KPORT_BIND_READABLE);
    test_check(rc == 0, "kobj_ops bind port");
    if (rc < 0)
        goto out;

    rc = kobj_signal(rx_obj, KPORT_BIND_READABLE, 0);
    test_check(rc == 0, "kobj_ops signal channel");

    struct kairos_port_packet_user pkt = {0};
    size_t pkt_len = 0;
    rc = kobj_read(port_obj, &pkt, sizeof(pkt), &pkt_len, KOBJ_IO_NONBLOCK);
    test_check(rc == 0 && pkt_len == sizeof(pkt), "kobj_ops read port");
    if (rc == 0) {
        test_check(pkt.key == 0x1234, "kobj_ops packet key");
        test_check((pkt.observed & KPORT_BIND_READABLE) != 0,
                   "kobj_ops packet signal");
    }

    kobj_get(rx_obj);
    kobj_put(rx_obj);

    struct kobj_refcount_history_entry hist[KOBJ_REFCOUNT_HISTORY_DEPTH] = {0};
    size_t hist_count =
        kobj_refcount_history_snapshot(rx_obj, hist, KOBJ_REFCOUNT_HISTORY_DEPTH);
    test_check(hist_count > 0, "kobj_refhist snapshot");
    bool saw_init = false;
    bool saw_get = false;
    bool saw_put = false;
    for (size_t i = 0; i < hist_count; i++) {
        if (hist[i].event == KOBJ_REFCOUNT_INIT)
            saw_init = true;
        else if (hist[i].event == KOBJ_REFCOUNT_GET)
            saw_get = true;
        else if (hist[i].event == KOBJ_REFCOUNT_PUT)
            saw_put = true;
    }
    test_check(saw_init, "kobj_refhist init");
    test_check(saw_get, "kobj_refhist get");
    test_check(saw_put, "kobj_refhist put");

    struct process *p = proc_current();
    int32_t src_handle = -1;
    bool src_handle_live = false;
    struct kobj *moved_obj = NULL;
    uint32_t moved_rights = 0;
    if (p) {
        src_handle = khandle_alloc(p, rx_obj, KRIGHT_CHANNEL_DEFAULT);
        src_handle_live = (src_handle >= 0);
        test_check(src_handle >= 0, "kobj_xferhist alloc source handle");
        if (src_handle >= 0) {
            rc = khandle_take_for_access(p, src_handle, KOBJ_ACCESS_TRANSFER,
                                         &moved_obj, &moved_rights);
            test_check(rc == 0 && moved_obj != NULL,
                       "kobj_xferhist take transfer");
            if (rc == 0 && moved_obj) {
                src_handle_live = false;
                rc = khandle_install_transferred(p, moved_obj, moved_rights,
                                                 &moved_handle);
                test_check(rc == 0 && moved_handle >= 0,
                           "kobj_xferhist install transfer");
                if (rc == 0 && moved_handle >= 0) {
                    khandle_transfer_drop_with_rights(moved_obj, moved_rights);
                    moved_obj = NULL;
                } else {
                    if (khandle_restore(p, src_handle, moved_obj, moved_rights) ==
                        0)
                        src_handle_live = true;
                    moved_obj = NULL;
                }
            }
        }
    }

    struct kobj_transfer_history_entry xhist[KOBJ_TRANSFER_HISTORY_DEPTH] = {0};
    size_t xhist_count = kobj_transfer_history_snapshot(
        rx_obj, xhist, KOBJ_TRANSFER_HISTORY_DEPTH);
    test_check(xhist_count > 0, "kobj_xferhist snapshot");
    bool saw_take = false;
    bool saw_install = false;
    for (size_t i = 0; i < xhist_count; i++) {
        if (xhist[i].event == KOBJ_TRANSFER_TAKE)
            saw_take = true;
        else if (xhist[i].event == KOBJ_TRANSFER_INSTALL)
            saw_install = true;
    }
    test_check(saw_take, "kobj_xferhist take");
    test_check(saw_install, "kobj_xferhist install");

out:
    if (src_handle_live && src_handle >= 0)
        (void)khandle_close(proc_current(), src_handle);
    if (moved_handle >= 0)
        (void)khandle_close(proc_current(), moved_handle);
    if (moved_obj)
        khandle_transfer_drop_with_rights(moved_obj, moved_rights);
    if (port_obj)
        kobj_put(port_obj);
    if (rx_obj)
        kobj_put(rx_obj);
    if (tx_obj)
        kobj_put(tx_obj);
}

static void test_kchannel_inline_queue_zero_heap(void) {
#if CONFIG_KERNEL_FAULT_INJECT
    struct kobj *tx_obj = NULL;
    struct kobj *rx_obj = NULL;
    int rc = kchannel_create_pair(&tx_obj, &rx_obj);
    test_check(rc == 0, "kchannel_inline create pair");
    if (rc < 0)
        return;

    uint8_t small_payload[32] = "inline-zero-heap";
    size_t got_bytes = 0;
    size_t got_handles = 0;
    bool truncated = false;
    uint8_t out[sizeof(small_payload)] = {0};

    fault_inject_reset();
    fault_inject_set_rate_permille(FAULT_INJECT_POINT_KMALLOC, 1000);
    fault_inject_set_warmup_hits(FAULT_INJECT_POINT_KMALLOC, 0);
    fault_inject_set_fail_budget(FAULT_INJECT_POINT_KMALLOC, 1);
    fault_inject_enable(true);
    fault_inject_scope_enter();
    rc = kchannel_send(tx_obj, small_payload, sizeof(small_payload), NULL, 0, 0);
    fault_inject_scope_exit();
    fault_inject_enable(false);

    test_check(rc == 0, "kchannel_inline send under kmalloc fault");
    test_check(fault_inject_failures(FAULT_INJECT_POINT_KMALLOC) == 0,
               "kchannel_inline small path no kmalloc");
    if (rc == 0) {
        rc = kchannel_recv(rx_obj, out, sizeof(out), &got_bytes, NULL, 0,
                           &got_handles, &truncated, KCHANNEL_OPT_NONBLOCK);
        test_check(rc == 0, "kchannel_inline recv");
        if (rc == 0) {
            test_check(got_bytes == sizeof(small_payload),
                       "kchannel_inline recv bytes");
            test_check(got_handles == 0, "kchannel_inline recv handles");
            test_check(!truncated, "kchannel_inline recv truncate");
            test_check(memcmp(out, small_payload, sizeof(small_payload)) == 0,
                       "kchannel_inline payload");
        }
    }

    uint8_t large_payload[KCHANNEL_INLINE_MSG_BYTES + 1] = {0};
    for (size_t i = 0; i < sizeof(large_payload); i++)
        large_payload[i] = (uint8_t)(i & 0xff);

    fault_inject_reset();
    fault_inject_set_rate_permille(FAULT_INJECT_POINT_KMALLOC, 1000);
    fault_inject_set_warmup_hits(FAULT_INJECT_POINT_KMALLOC, 0);
    fault_inject_set_fail_budget(FAULT_INJECT_POINT_KMALLOC, 1);
    fault_inject_enable(true);
    fault_inject_scope_enter();
    rc = kchannel_send(tx_obj, large_payload, sizeof(large_payload), NULL, 0, 0);
    fault_inject_scope_exit();
    fault_inject_enable(false);

    test_check(rc == -ENOMEM, "kchannel_inline large path kmalloc fail");
    test_check(fault_inject_failures(FAULT_INJECT_POINT_KMALLOC) == 1,
               "kchannel_inline large path hit kmalloc");
    fault_inject_reset();

    if (rx_obj)
        kobj_put(rx_obj);
    if (tx_obj)
        kobj_put(tx_obj);
#endif
}

static void run_syscall_trap_tests_full(void) {
    test_syscall_table_slot_coverage();
    test_syscall_invalid_num_legacy();
    test_syscall_unimplemented_slot_legacy();
    test_syscall_identity_legacy();
    test_syscall_error_paths_legacy();
    test_uaccess_cross_page_regression();
    test_uaccess_large_range_regression();
    test_strncpy_from_user_len_regression();
    test_strncpy_from_user_unmapped_tail_regression();
    test_strncpy_from_user_nul_before_unmapped_tail_regression();
    test_uaccess_arg_validation_regression();
    test_sched_affinity_syscalls_regression();
    test_sched_policy_syscalls_regression();
    test_mount_umount_flag_semantics();
    test_mount_propagation_recursive_semantics();
    test_acct_syscall_semantics();
    test_futex_waitv_syscalls_regression();
    test_trap_dispatch_guard_clauses();
    test_trap_dispatch_sets_and_restores_tf();
    test_trap_dispatch_restores_preexisting_tf();
    test_get_current_trapframe_process_fallback();
    test_kairos_cap_rights_fd_syscalls();
    test_kairos_channel_port_syscalls();
    test_kairos_channel_port_stress_mpmc();
    test_kairos_file_handle_bridge();
    test_kobj_ops_refcount_history();
    test_kchannel_inline_queue_zero_heap();
    test_syscall_user_e2e();
}

static void run_syscall_trap_tests_ipc_cap_only(void) {
    test_kairos_cap_rights_fd_syscalls();
    test_kairos_channel_port_syscalls();
    test_kairos_channel_port_stress_mpmc();
    test_kairos_file_handle_bridge();
    test_kobj_ops_refcount_history();
    test_kchannel_inline_queue_zero_heap();
}

int run_syscall_trap_tests(void) {
    tests_failed = 0;
    pr_info("Running syscall/trap tests...\n");

    if (CONFIG_SYSCALL_TRAP_IPC_CAP_ONLY) {
        pr_info("syscall_trap_tests: ipc/cap focused subset enabled\n");
        run_syscall_trap_tests_ipc_cap_only();
    } else {
        run_syscall_trap_tests_full();
    }

    if (tests_failed == 0)
        pr_info("syscall/trap tests: all passed\n");
    else
        pr_err("syscall/trap tests: %d failures\n", tests_failed);

    return tests_failed;
}

#else

int run_syscall_trap_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
