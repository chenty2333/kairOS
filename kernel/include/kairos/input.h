/**
 * kernel/include/kairos/input.h - Input Device Subsystem
 *
 * Generic input device framework for keyboards, mice, touchpads, etc.
 * Compatible with Linux input event protocol.
 */

#ifndef _KAIROS_INPUT_H
#define _KAIROS_INPUT_H

#include <kairos/list.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>

struct input_dev;
struct input_event;

/* Input event structure (Linux compatible) */
struct input_event {
    uint64_t time_sec;
    uint64_t time_usec;
    uint16_t type;
    uint16_t code;
    int32_t value;
};

/* Event types */
#define EV_SYN 0x00
#define EV_KEY 0x01
#define EV_REL 0x02
#define EV_ABS 0x03

/* Synchronization events */
#define SYN_REPORT 0

/* Key codes (subset, compatible with Linux input.h) */
#define KEY_RESERVED 0
#define KEY_ESC 1
#define KEY_1 2
#define KEY_2 3
#define KEY_3 4
#define KEY_4 5
#define KEY_5 6
#define KEY_6 7
#define KEY_7 8
#define KEY_8 9
#define KEY_9 10
#define KEY_0 11
#define KEY_MINUS 12
#define KEY_EQUAL 13
#define KEY_BACKSPACE 14
#define KEY_TAB 15
#define KEY_Q 16
#define KEY_W 17
#define KEY_E 18
#define KEY_R 19
#define KEY_T 20
#define KEY_Y 21
#define KEY_U 22
#define KEY_I 23
#define KEY_O 24
#define KEY_P 25
#define KEY_LEFTBRACE 26
#define KEY_RIGHTBRACE 27
#define KEY_ENTER 28
#define KEY_LEFTCTRL 29
#define KEY_A 30
#define KEY_S 31
#define KEY_D 32
#define KEY_F 33
#define KEY_G 34
#define KEY_H 35
#define KEY_J 36
#define KEY_K 37
#define KEY_L 38
#define KEY_SEMICOLON 39
#define KEY_APOSTROPHE 40
#define KEY_GRAVE 41
#define KEY_LEFTSHIFT 42
#define KEY_BACKSLASH 43
#define KEY_Z 44
#define KEY_X 45
#define KEY_C 46
#define KEY_V 47
#define KEY_B 48
#define KEY_N 49
#define KEY_M 50
#define KEY_COMMA 51
#define KEY_DOT 52
#define KEY_SLASH 53
#define KEY_RIGHTSHIFT 54
#define KEY_KPASTERISK 55
#define KEY_LEFTALT 56
#define KEY_SPACE 57
#define KEY_CAPSLOCK 58
#define KEY_F1 59
#define KEY_F2 60
#define KEY_F3 61
#define KEY_F4 62
#define KEY_F5 63
#define KEY_F6 64
#define KEY_F7 65
#define KEY_F8 66
#define KEY_F9 67
#define KEY_F10 68
#define KEY_NUMLOCK 69
#define KEY_SCROLLLOCK 70
#define KEY_KP7 71
#define KEY_KP8 72
#define KEY_KP9 73
#define KEY_KPMINUS 74
#define KEY_KP4 75
#define KEY_KP5 76
#define KEY_KP6 77
#define KEY_KPPLUS 78
#define KEY_KP1 79
#define KEY_KP2 80
#define KEY_KP3 81
#define KEY_KP0 82
#define KEY_KPDOT 83
#define KEY_F11 87
#define KEY_F12 88
#define KEY_KPENTER 96
#define KEY_RIGHTCTRL 97
#define KEY_KPSLASH 98
#define KEY_SYSRQ 99
#define KEY_RIGHTALT 100
#define KEY_HOME 102
#define KEY_UP 103
#define KEY_PAGEUP 104
#define KEY_LEFT 105
#define KEY_RIGHT 106
#define KEY_END 107
#define KEY_DOWN 108
#define KEY_PAGEDOWN 109
#define KEY_INSERT 110
#define KEY_DELETE 111

/* Button codes */
#define BTN_MISC 0x100
#define BTN_0 0x100
#define BTN_1 0x101
#define BTN_2 0x102
#define BTN_3 0x103
#define BTN_4 0x104
#define BTN_5 0x105
#define BTN_6 0x106
#define BTN_7 0x107
#define BTN_8 0x108
#define BTN_9 0x109

#define BTN_MOUSE 0x110
#define BTN_LEFT 0x110
#define BTN_RIGHT 0x111
#define BTN_MIDDLE 0x112
#define BTN_SIDE 0x113
#define BTN_EXTRA 0x114
#define BTN_FORWARD 0x115
#define BTN_BACK 0x116

/* Relative axes */
#define REL_X 0x00
#define REL_Y 0x01
#define REL_Z 0x02
#define REL_WHEEL 0x08
#define REL_HWHEEL 0x06

/* Bus types */
#define BUS_PCI 0x01
#define BUS_ISAPNP 0x02
#define BUS_USB 0x03
#define BUS_HIL 0x04
#define BUS_BLUETOOTH 0x05
#define BUS_VIRTUAL 0x06
#define BUS_ISA 0x10
#define BUS_I8042 0x11
#define BUS_XTKBD 0x12
#define BUS_RS232 0x13
#define BUS_GAMEPORT 0x14
#define BUS_PARPORT 0x15
#define BUS_AMIGA 0x16
#define BUS_ADB 0x17
#define BUS_I2C 0x18
#define BUS_HOST 0x19
#define BUS_GSC 0x1A
#define BUS_ATARI 0x1B
#define BUS_SPI 0x1C

/* Input device structure */
struct input_dev {
    char name[64];
    uint16_t id_bus;
    uint16_t id_vendor;
    uint16_t id_product;
    uint16_t id_version;

    spinlock_t lock;
    struct list_head client_list;
    struct list_head node;

    void *driver_data;
};

/* Core API */
struct input_dev *input_dev_alloc(void);
void input_dev_free(struct input_dev *dev);
int input_dev_register(struct input_dev *dev);
void input_dev_unregister(struct input_dev *dev);

/* Event reporting */
void input_report_key(struct input_dev *dev, uint16_t code, int32_t value);
void input_report_rel(struct input_dev *dev, uint16_t code, int32_t value);
void input_report_abs(struct input_dev *dev, uint16_t code, int32_t value);
void input_sync(struct input_dev *dev);

/* Internal API for evdev */
struct input_dev *input_dev_get_by_index(int index);
int input_dev_get_count(void);

#endif /* _KAIROS_INPUT_H */
