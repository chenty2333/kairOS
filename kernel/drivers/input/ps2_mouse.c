/**
 * kernel/drivers/input/ps2_mouse.c - PS/2 Mouse Driver
 *
 * Handles IRQ 12 and decodes 3/4-byte mouse packets.
 */

#ifdef __x86_64__

#include <kairos/arch.h>
#include <kairos/input.h>
#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/types.h>

#define PS2_MOUSE_IRQ 12
#define PS2_DATA_PORT 0x60
#define PS2_CMD_PORT 0x64

#define PS2_CMD_WRITE_AUX 0xD4
#define PS2_MOUSE_CMD_ENABLE 0xF4
#define PS2_MOUSE_CMD_SET_SAMPLE_RATE 0xF3
#define PS2_MOUSE_CMD_GET_ID 0xF2

#define PS2_STATUS_OUTPUT_FULL 0x01
#define PS2_STATUS_INPUT_FULL 0x02

struct ps2_mouse_state {
    struct input_dev *input_dev;
    uint8_t pkt[4];
    uint8_t pkt_idx;
    bool has_wheel;
    spinlock_t lock;
};

static struct ps2_mouse_state *mouse_state;

static void ps2_wait_input_clear(void) {
    for (int i = 0; i < 1000; i++) {
        if (!(inb(PS2_CMD_PORT) & PS2_STATUS_INPUT_FULL))
            return;
    }
}

static void ps2_wait_output_ready(void) {
    for (int i = 0; i < 1000; i++) {
        if (inb(PS2_CMD_PORT) & PS2_STATUS_OUTPUT_FULL)
            return;
    }
}

static void ps2_mouse_write(uint8_t cmd) {
    ps2_wait_input_clear();
    outb(PS2_CMD_PORT, PS2_CMD_WRITE_AUX);
    ps2_wait_input_clear();
    outb(PS2_DATA_PORT, cmd);
}

static uint8_t ps2_mouse_read(void) {
    ps2_wait_output_ready();
    return inb(PS2_DATA_PORT);
}

static uint8_t ps2_mouse_read_id(void) {
    ps2_mouse_write(PS2_MOUSE_CMD_GET_ID);
    ps2_mouse_read();
    return ps2_mouse_read();
}

static void ps2_mouse_irq(void *arg, const struct trap_core_event *ev) {
    (void)ev;
    struct ps2_mouse_state *state = arg;
    uint8_t byte = inb(PS2_DATA_PORT);

    bool irq_state = arch_irq_save();
    spin_lock(&state->lock);

    if (state->pkt_idx == 0 && !(byte & 0x08)) {
        spin_unlock(&state->lock);
        arch_irq_restore(irq_state);
        return;
    }

    state->pkt[state->pkt_idx++] = byte;

    int pkt_size = state->has_wheel ? 4 : 3;
    if (state->pkt_idx < pkt_size) {
        spin_unlock(&state->lock);
        arch_irq_restore(irq_state);
        return;
    }

    state->pkt_idx = 0;

    uint8_t *pkt = state->pkt;
    int dx = pkt[1] - ((pkt[0] & 0x10) ? 256 : 0);
    int dy = pkt[2] - ((pkt[0] & 0x20) ? 256 : 0);
    dy = -dy;

    input_report_key(state->input_dev, BTN_LEFT, (pkt[0] & 0x01) ? 1 : 0);
    input_report_key(state->input_dev, BTN_RIGHT, (pkt[0] & 0x02) ? 1 : 0);
    input_report_key(state->input_dev, BTN_MIDDLE, (pkt[0] & 0x04) ? 1 : 0);

    if (dx)
        input_report_rel(state->input_dev, REL_X, dx);
    if (dy)
        input_report_rel(state->input_dev, REL_Y, dy);

    if (state->has_wheel && (int8_t)pkt[3])
        input_report_rel(state->input_dev, REL_WHEEL, (int8_t)pkt[3]);

    input_sync(state->input_dev);

    spin_unlock(&state->lock);
    arch_irq_restore(irq_state);
}

int ps2_mouse_init(void) {
    pr_info("ps2_mouse: initializing mouse driver\n");

    ps2_wait_input_clear();
    outb(PS2_CMD_PORT, 0xA8);

    ps2_mouse_write(PS2_MOUSE_CMD_SET_SAMPLE_RATE);
    ps2_mouse_read();
    ps2_mouse_write(200);
    ps2_mouse_read();

    ps2_mouse_write(PS2_MOUSE_CMD_SET_SAMPLE_RATE);
    ps2_mouse_read();
    ps2_mouse_write(100);
    ps2_mouse_read();

    ps2_mouse_write(PS2_MOUSE_CMD_SET_SAMPLE_RATE);
    ps2_mouse_read();
    ps2_mouse_write(80);
    ps2_mouse_read();

    uint8_t id = ps2_mouse_read_id();
    bool has_wheel = (id == 3);

    pr_info("ps2_mouse: detected mouse ID=%d (wheel=%d)\n", id, has_wheel);

    struct input_dev *dev = input_dev_alloc();
    if (!dev)
        return -ENOMEM;

    strncpy(dev->name, "PS/2 Mouse", sizeof(dev->name) - 1);
    dev->name[sizeof(dev->name) - 1] = '\0';
    dev->id_bus = BUS_I8042;
    dev->id_vendor = 0x0002;
    dev->id_product = 0x0001;
    dev->id_version = 0x0100;

    mouse_state = kzalloc(sizeof(*mouse_state));
    if (!mouse_state) {
        input_dev_free(dev);
        return -ENOMEM;
    }

    spin_init(&mouse_state->lock);
    mouse_state->input_dev = dev;
    mouse_state->pkt_idx = 0;
    mouse_state->has_wheel = has_wheel;
    dev->driver_data = mouse_state;

    int ret = input_dev_register(dev);
    if (ret < 0) {
        kfree(mouse_state);
        input_dev_free(dev);
        return ret;
    }

    ps2_mouse_write(PS2_MOUSE_CMD_ENABLE);
    ps2_mouse_read();

    arch_request_irq_ex(PS2_MOUSE_IRQ, ps2_mouse_irq, mouse_state,
                        IRQ_FLAG_TRIGGER_EDGE);

    pr_info("ps2_mouse: mouse driver initialized\n");
    return 0;
}

#endif /* __x86_64__ */
