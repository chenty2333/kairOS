/**
 * kernel/drivers/input/ps2_kbd.c - PS/2 Keyboard Driver
 *
 * Handles IRQ 1 and translates scancodes to Linux key codes.
 */

#ifdef __x86_64__

#include <kairos/arch.h>
#include <kairos/input.h>
#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/tty.h>
#include <kairos/types.h>

#define PS2_KBD_IRQ 1
#define PS2_DATA_PORT 0x60

struct ps2_kbd_state {
    struct input_dev *input_dev;
    bool extended;
    bool shift;
    bool ctrl;
    bool alt;
    spinlock_t lock;
};

static struct ps2_kbd_state *kbd_state;

extern struct tty_struct *console_tty_get(void);
extern void tty_receive_buf(struct tty_struct *tty, const uint8_t *buf, size_t count);

/* Scancode set 1 to Linux keycode mapping */
static const uint16_t scancode_map[128] = {
    0, KEY_ESC, KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6,
    KEY_7, KEY_8, KEY_9, KEY_0, KEY_MINUS, KEY_EQUAL, KEY_BACKSPACE, KEY_TAB,
    KEY_Q, KEY_W, KEY_E, KEY_R, KEY_T, KEY_Y, KEY_U, KEY_I,
    KEY_O, KEY_P, KEY_LEFTBRACE, KEY_RIGHTBRACE, KEY_ENTER, KEY_LEFTCTRL, KEY_A, KEY_S,
    KEY_D, KEY_F, KEY_G, KEY_H, KEY_J, KEY_K, KEY_L, KEY_SEMICOLON,
    KEY_APOSTROPHE, KEY_GRAVE, KEY_LEFTSHIFT, KEY_BACKSLASH, KEY_Z, KEY_X, KEY_C, KEY_V,
    KEY_B, KEY_N, KEY_M, KEY_COMMA, KEY_DOT, KEY_SLASH, KEY_RIGHTSHIFT, KEY_KPASTERISK,
    KEY_LEFTALT, KEY_SPACE, KEY_CAPSLOCK, KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5,
    KEY_F6, KEY_F7, KEY_F8, KEY_F9, KEY_F10, KEY_NUMLOCK, KEY_SCROLLLOCK, KEY_KP7,
    KEY_KP8, KEY_KP9, KEY_KPMINUS, KEY_KP4, KEY_KP5, KEY_KP6, KEY_KPPLUS, KEY_KP1,
    KEY_KP2, KEY_KP3, KEY_KP0, KEY_KPDOT, 0, 0, 0, KEY_F11,
    KEY_F12, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
};

/* Extended scancode (0xE0 prefix) mapping */
static const uint16_t scancode_ext_map[128] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, KEY_KPENTER, KEY_RIGHTCTRL, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, KEY_KPSLASH, 0, KEY_SYSRQ,
    KEY_RIGHTALT, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, KEY_HOME,
    KEY_UP, KEY_PAGEUP, 0, KEY_LEFT, 0, KEY_RIGHT, 0, KEY_END,
    KEY_DOWN, KEY_PAGEDOWN, KEY_INSERT, KEY_DELETE, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
};

/* Simple keycode to ASCII conversion */
static char keycode_to_ascii(uint16_t keycode, bool shift, bool ctrl) {
    if (ctrl) {
        if (keycode >= KEY_A && keycode <= KEY_Z)
            return (char)(keycode - KEY_A + 1);
        return 0;
    }

    if (keycode >= KEY_A && keycode <= KEY_Z) {
        char base = 'a' + (keycode - KEY_A);
        return shift ? (base - 32) : base;
    }

    if (keycode >= KEY_1 && keycode <= KEY_9) {
        if (shift) {
            const char shifted[] = "!@#$%^&*()";
            return shifted[keycode - KEY_1];
        }
        return '1' + (keycode - KEY_1);
    }

    if (keycode == KEY_0)
        return shift ? ')' : '0';

    switch (keycode) {
    case KEY_SPACE: return ' ';
    case KEY_ENTER: return '\n';
    case KEY_TAB: return '\t';
    case KEY_BACKSPACE: return '\b';
    case KEY_MINUS: return shift ? '_' : '-';
    case KEY_EQUAL: return shift ? '+' : '=';
    case KEY_LEFTBRACE: return shift ? '{' : '[';
    case KEY_RIGHTBRACE: return shift ? '}' : ']';
    case KEY_SEMICOLON: return shift ? ':' : ';';
    case KEY_APOSTROPHE: return shift ? '"' : '\'';
    case KEY_GRAVE: return shift ? '~' : '`';
    case KEY_BACKSLASH: return shift ? '|' : '\\';
    case KEY_COMMA: return shift ? '<' : ',';
    case KEY_DOT: return shift ? '>' : '.';
    case KEY_SLASH: return shift ? '?' : '/';
    default: return 0;
    }
}

static void ps2_kbd_irq(void *arg, const struct trap_core_event *ev) {
    (void)ev;
    struct ps2_kbd_state *state = arg;
    uint8_t scancode = inb(PS2_DATA_PORT);

    bool irq_state = arch_irq_save();
    spin_lock(&state->lock);

    if (scancode == 0xE0) {
        state->extended = true;
        spin_unlock(&state->lock);
        arch_irq_restore(irq_state);
        return;
    }

    bool release = (scancode & 0x80) != 0;
    scancode &= 0x7F;

    uint16_t keycode;
    if (state->extended) {
        keycode = scancode_ext_map[scancode];
        state->extended = false;
    } else {
        keycode = scancode_map[scancode];
    }

    if (keycode) {
        input_report_key(state->input_dev, keycode, release ? 0 : 1);
        input_sync(state->input_dev);

        if (keycode == KEY_LEFTSHIFT || keycode == KEY_RIGHTSHIFT)
            state->shift = !release;
        if (keycode == KEY_LEFTCTRL || keycode == KEY_RIGHTCTRL)
            state->ctrl = !release;
        if (keycode == KEY_LEFTALT || keycode == KEY_RIGHTALT)
            state->alt = !release;

        if (!release) {
            char ch = keycode_to_ascii(keycode, state->shift, state->ctrl);
            if (ch) {
                spin_unlock(&state->lock);
                arch_irq_restore(irq_state);

                struct tty_struct *tty = console_tty_get();
                if (tty) {
                    uint8_t buf[1] = { (uint8_t)ch };
                    tty_receive_buf(tty, buf, 1);
                }
                return;
            }
        }
    }

    spin_unlock(&state->lock);
    arch_irq_restore(irq_state);
}

int ps2_kbd_init(void) {
    pr_info("ps2_kbd: initializing keyboard driver\n");

    struct input_dev *dev = input_dev_alloc();
    if (!dev)
        return -ENOMEM;

    strncpy(dev->name, "AT Keyboard", sizeof(dev->name) - 1);
    dev->name[sizeof(dev->name) - 1] = '\0';
    dev->id_bus = BUS_I8042;
    dev->id_vendor = 0x0001;
    dev->id_product = 0x0001;
    dev->id_version = 0x0100;

    kbd_state = kzalloc(sizeof(*kbd_state));
    if (!kbd_state) {
        input_dev_free(dev);
        return -ENOMEM;
    }

    spin_init(&kbd_state->lock);
    kbd_state->input_dev = dev;
    kbd_state->extended = false;
    kbd_state->shift = false;
    kbd_state->ctrl = false;
    kbd_state->alt = false;
    dev->driver_data = kbd_state;

    int ret = input_dev_register(dev);
    if (ret < 0) {
        kfree(kbd_state);
        input_dev_free(dev);
        return ret;
    }

    arch_request_irq_ex(PS2_KBD_IRQ, ps2_kbd_irq, kbd_state,
                        IRQ_FLAG_TRIGGER_EDGE);

    pr_info("ps2_kbd: keyboard driver initialized\n");
    return 0;
}

#endif /* __x86_64__ */
