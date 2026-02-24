/**
 * kernel/core/trap/trap_core.c - Core trap dispatch boundary
 */

#include <kairos/sched.h>
#include <kairos/process.h>
#include <kairos/signal.h>
#include <kairos/trap_core.h>

void trap_core_dispatch(const struct trap_core_event *ev,
                        const struct trap_core_ops *ops) {
    if (!ev || !ev->tf || !ops || !ops->handle_event ||
        !ops->should_deliver_signals) {
        return;
    }

    struct percpu_data *cpu = arch_get_percpu();
    struct trap_frame *old_tf = cpu->current_tf;
    struct process *curr = proc_current();
    void *old_proc_tf = curr ? curr->active_tf : NULL;
    cpu->current_tf = ev->tf;
    if (curr)
        curr->active_tf = ev->tf;

    (void)ops->handle_event(ev);

    if (ops->should_deliver_signals(ev)) {
        signal_deliver_pending();
    }

    if (curr)
        curr->active_tf = old_proc_tf;
    cpu->current_tf = old_tf;
}
