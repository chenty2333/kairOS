/**
 * kernel/drivers/input/ps2_controller.c - PS/2 Controller (8042) Initialization
 *
 * Initializes the Intel 8042 PS/2 controller for keyboard and mouse.
 */

#ifdef __x86_64__

#include <kairos/printk.h>
#include <kairos/types.h>
#include <kairos/arch.h>

#define PS2_DATA_PORT 0x60
#define PS2_CMD_PORT 0x64

#define PS2_CMD_READ_CONFIG 0x20
#define PS2_CMD_WRITE_CONFIG 0x60
#define PS2_CMD_DISABLE_PORT1 0xAD
#define PS2_CMD_ENABLE_PORT1 0xAE
#define PS2_CMD_DISABLE_PORT2 0xA7
#define PS2_CMD_ENABLE_PORT2 0xA8

#define PS2_STATUS_OUTPUT_FULL 0x01
#define PS2_STATUS_INPUT_FULL 0x02

static inline uint8_t ps2_read_status(void) {
    return inb(PS2_CMD_PORT);
}

static inline uint8_t ps2_read_data(void) {
    return inb(PS2_DATA_PORT);
}

static inline void ps2_write_cmd(uint8_t cmd) {
    outb(PS2_CMD_PORT, cmd);
}

static inline void ps2_write_data(uint8_t data) {
    outb(PS2_DATA_PORT, data);
}

static void ps2_wait_input_clear(void) {
    for (int i = 0; i < 1000; i++) {
        if (!(ps2_read_status() & PS2_STATUS_INPUT_FULL))
            return;
    }
}

static void ps2_wait_output_ready(void) {
    for (int i = 0; i < 1000; i++) {
        if (ps2_read_status() & PS2_STATUS_OUTPUT_FULL)
            return;
    }
}

void ps2_controller_init(void) {
    pr_info("ps2: initializing 8042 controller\n");

    ps2_write_cmd(PS2_CMD_DISABLE_PORT1);
    ps2_write_cmd(PS2_CMD_DISABLE_PORT2);

    while (ps2_read_status() & PS2_STATUS_OUTPUT_FULL)
        ps2_read_data();

    ps2_write_cmd(PS2_CMD_READ_CONFIG);
    ps2_wait_output_ready();
    uint8_t config = ps2_read_data();

    config |= 0x03;
    config &= ~0x40;

    ps2_wait_input_clear();
    ps2_write_cmd(PS2_CMD_WRITE_CONFIG);
    ps2_wait_input_clear();
    ps2_write_data(config);

    ps2_wait_input_clear();
    ps2_write_cmd(PS2_CMD_ENABLE_PORT1);
    ps2_wait_input_clear();
    ps2_write_cmd(PS2_CMD_ENABLE_PORT2);

    pr_info("ps2: controller initialized\n");
}

#endif /* __x86_64__ */
