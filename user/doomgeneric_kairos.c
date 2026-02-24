// DoomGeneric platform layer for Kairos

#include "doomgeneric.h"
#include "doomkeys.h"
#include "i_system.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

#define DRM_LITE_IOC_GET_INFO       0xF001
#define DRM_LITE_IOC_CREATE_BUFFER  0xF002
#define DRM_LITE_IOC_MAP_BUFFER     0xF003
#define DRM_LITE_IOC_PRESENT        0xF004
#define DRM_LITE_IOC_DESTROY_BUFFER 0xF005

#define DRM_LITE_FORMAT_XRGB8888 1

struct drm_lite_info {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t format;
    uint32_t max_buffers;
};

struct drm_lite_create {
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t handle;
    uint32_t pitch;
    uint64_t size;
};

struct drm_lite_map {
    uint32_t handle;
    uint64_t user_va;
};

struct drm_lite_present {
    uint32_t handle;
    uint32_t flags;
};

struct key_event {
    int pressed;
    unsigned char key;
};

#define KEY_QUEUE_SIZE 64
#define KEY_STATE_SIZE 256
#define HOLD_TIMEOUT_MS 80

static struct key_event key_queue[KEY_QUEUE_SIZE];
static unsigned int key_read_idx;
static unsigned int key_write_idx;

struct key_state {
    int down;
    uint32_t last_ms;
};

static struct key_state key_states[KEY_STATE_SIZE];

static int drm_fd = -1;
static int console_fd = -1;
static struct termios console_termios;
static int console_termios_valid;

static uint8_t *fb_ptr;
static uint32_t fb_pitch;
static uint32_t fb_width = DOOMGENERIC_RESX;
static uint32_t fb_height = DOOMGENERIC_RESY;
static uint32_t fb_handle;

static uint64_t tick_start_ms;

static void restore_console(void) {
    if (console_termios_valid && console_fd >= 0) {
        tcsetattr(console_fd, TCSANOW, &console_termios);
    }
}

static void queue_key_event(int pressed, unsigned char key) {
    unsigned int next = (key_write_idx + 1) % KEY_QUEUE_SIZE;
    if (next == key_read_idx) {
        return;
    }
    key_queue[key_write_idx].pressed = pressed;
    key_queue[key_write_idx].key = key;
    key_write_idx = next;
}

static void queue_key_tap(unsigned char key) {
    queue_key_event(1, key);
    queue_key_event(0, key);
}

static int is_hold_key(unsigned char key) {
    switch (key) {
    case KEY_UPARROW:
    case KEY_DOWNARROW:
    case KEY_LEFTARROW:
    case KEY_RIGHTARROW:
    case KEY_FIRE:
    case KEY_USE:
    case KEY_LALT:
    case KEY_RSHIFT:
        return 1;
    default:
        return 0;
    }
}

static void handle_hold_key(unsigned char key) {
    uint32_t now = DG_GetTicksMs();
    queue_key_event(1, key);
    key_states[key].down = 1;
    key_states[key].last_ms = now;
}

static void handle_key(unsigned char key) {
    if (!is_hold_key(key)) {
        queue_key_tap(key);
        return;
    }

    handle_hold_key(key);
}

static void expire_keys(void) {
    uint32_t now = DG_GetTicksMs();
    for (unsigned int key = 0; key < KEY_STATE_SIZE; key++) {
        if (!key_states[key].down)
            continue;
        uint32_t delta = now - key_states[key].last_ms;
        if (delta > HOLD_TIMEOUT_MS) {
            key_states[key].down = 0;
            queue_key_event(0, (unsigned char)key);
        }
    }
}

static int console_read_byte(unsigned char *out) {
    int avail = 0;
    if (console_fd < 0)
        return 0;
    if (ioctl(console_fd, FIONREAD, &avail) < 0 || avail <= 0)
        return 0;
    ssize_t n = read(console_fd, out, 1);
    return n == 1;
}

static unsigned char map_ascii_key(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z')
        return (unsigned char)('a' + (ch - 'A'));
    return ch;
}

static void poll_input(void) {
    unsigned char ch;
    while (console_read_byte(&ch)) {
        if (ch == 0x1b) {
            unsigned char seq1 = 0;
            unsigned char seq2 = 0;
            if (!console_read_byte(&seq1)) {
                queue_key_tap(KEY_ESCAPE);
                continue;
            }
            if (seq1 == '[') {
                if (!console_read_byte(&seq2)) {
                    queue_key_tap(KEY_ESCAPE);
                    continue;
                }
                switch (seq2) {
                case 'A':
                    handle_key(KEY_UPARROW);
                    break;
                case 'B':
                    handle_key(KEY_DOWNARROW);
                    break;
                case 'C':
                    handle_key(KEY_RIGHTARROW);
                    break;
                case 'D':
                    handle_key(KEY_LEFTARROW);
                    break;
                default:
                    queue_key_tap(KEY_ESCAPE);
                    break;
                }
                continue;
            }
            queue_key_tap(KEY_ESCAPE);
            continue;
        }

        switch (ch) {
        case '\r':
        case '\n':
            queue_key_tap(KEY_ENTER);
            break;
        case '\t':
            queue_key_tap(KEY_TAB);
            break;
        case 0x7f:
        case '\b':
            queue_key_tap(KEY_BACKSPACE);
            break;
        case 'w':
        case 'W':
            handle_hold_key(KEY_UPARROW);
            handle_hold_key('w');
            break;
        case 's':
        case 'S':
            handle_hold_key(KEY_DOWNARROW);
            handle_hold_key('s');
            break;
        case 'a':
        case 'A':
            handle_hold_key(KEY_LEFTARROW);
            handle_hold_key('a');
            break;
        case 'd':
        case 'D':
            handle_hold_key(KEY_RIGHTARROW);
            handle_hold_key('d');
            break;
        case 'f':
        case 'F':
            handle_hold_key(KEY_FIRE);
            handle_hold_key('f');
            break;
        case 'e':
        case 'E':
            handle_hold_key(KEY_USE);
            handle_hold_key('e');
            break;
        case 'r':
        case 'R':
            handle_hold_key(KEY_RSHIFT);
            handle_hold_key('r');
            break;
        case ' ':
            handle_hold_key(KEY_USE);
            break;
        case 'q':
        case 'Q':
            queue_key_tap(KEY_ESCAPE);
            break;
        default:
            queue_key_tap(map_ascii_key(ch));
            break;
        }
    }
}

void DG_Init(void) {
    console_fd = open("/dev/console", O_RDWR);
    if (console_fd < 0) {
        console_fd = 0;
    }

    if (tcgetattr(console_fd, &console_termios) == 0) {
        struct termios raw = console_termios;
        raw.c_lflag &= ~(ICANON | ECHO);
        raw.c_iflag &= ~(ICRNL | INLCR | IGNCR);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        tcsetattr(console_fd, TCSANOW, &raw);
        console_termios_valid = 1;
        atexit(restore_console);
    }

    drm_fd = open("/dev/fb0", O_RDWR);
    if (drm_fd < 0) {
        I_Error("doom: open /dev/fb0 failed (%d)\n", errno);
        return;
    }

    struct drm_lite_info info;
    memset(&info, 0, sizeof(info));
    if (ioctl(drm_fd, DRM_LITE_IOC_GET_INFO, &info) < 0) {
        I_Error("doom: DRM_LITE_IOC_GET_INFO failed (%d)\n", errno);
        return;
    }

    if (info.width < DOOMGENERIC_RESX || info.height < DOOMGENERIC_RESY) {
        I_Error("doom: framebuffer too small (%ux%u, need %ux%u)\n",
                info.width, info.height,
                (uint32_t)DOOMGENERIC_RESX, (uint32_t)DOOMGENERIC_RESY);
        return;
    }

    fb_width = info.width;
    fb_height = info.height;

    struct drm_lite_create create;
    memset(&create, 0, sizeof(create));
    create.width = fb_width;
    create.height = fb_height;
    create.format = DRM_LITE_FORMAT_XRGB8888;

    if (ioctl(drm_fd, DRM_LITE_IOC_CREATE_BUFFER, &create) < 0) {
        I_Error("doom: DRM_LITE_IOC_CREATE_BUFFER failed (%d)\n", errno);
        return;
    }

    struct drm_lite_map map;
    memset(&map, 0, sizeof(map));
    map.handle = create.handle;
    if (ioctl(drm_fd, DRM_LITE_IOC_MAP_BUFFER, &map) < 0) {
        I_Error("doom: DRM_LITE_IOC_MAP_BUFFER failed (%d)\n", errno);
        return;
    }

    fb_ptr = (uint8_t *)(uintptr_t)map.user_va;
    fb_pitch = create.pitch;
    fb_handle = create.handle;

    memset(fb_ptr, 0, fb_pitch * fb_height);

    struct drm_lite_present present;
    memset(&present, 0, sizeof(present));
    present.handle = fb_handle;
    ioctl(drm_fd, DRM_LITE_IOC_PRESENT, &present);
}

void DG_DrawFrame(void) {
    if (!fb_ptr)
        return;

    if (fb_width == DOOMGENERIC_RESX && fb_height == DOOMGENERIC_RESY) {
        uint8_t *src = (uint8_t *)DG_ScreenBuffer;
        for (uint32_t y = 0; y < fb_height; y++) {
            memcpy(fb_ptr + y * fb_pitch, src + y * fb_width * 4,
                   fb_width * 4);
        }
    } else {
        const uint32_t *src = (const uint32_t *)DG_ScreenBuffer;
        for (uint32_t y = 0; y < fb_height; y++) {
            uint32_t src_y = (uint32_t)((uint64_t)y * DOOMGENERIC_RESY /
                                        fb_height);
            uint32_t *dst_row = (uint32_t *)(fb_ptr + y * fb_pitch);
            const uint32_t *src_row = src + src_y * DOOMGENERIC_RESX;
            for (uint32_t x = 0; x < fb_width; x++) {
                uint32_t src_x = (uint32_t)((uint64_t)x * DOOMGENERIC_RESX /
                                            fb_width);
                dst_row[x] = src_row[src_x];
            }
        }
    }

    struct drm_lite_present present;
    memset(&present, 0, sizeof(present));
    present.handle = fb_handle;
    ioctl(drm_fd, DRM_LITE_IOC_PRESENT, &present);
}

void DG_SleepMs(uint32_t ms) {
    usleep(ms * 1000);
}

uint32_t DG_GetTicksMs(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t now = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
    if (!tick_start_ms)
        tick_start_ms = now;
    return (uint32_t)(now - tick_start_ms);
}

int DG_GetKey(int *pressed, unsigned char *key) {
    poll_input();
    expire_keys();

    if (key_read_idx == key_write_idx)
        return 0;

    *pressed = key_queue[key_read_idx].pressed;
    *key = key_queue[key_read_idx].key;
    key_read_idx = (key_read_idx + 1) % KEY_QUEUE_SIZE;
    return 1;
}

void DG_SetWindowTitle(const char *title) {
    (void)title;
}

static int argv_has_iwad(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "-iwad") == 0)
            return 1;
    }
    return 0;
}

static int file_exists(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0;
}

int main(int argc, char **argv) {
    if (!argv) {
        static char *fallback_argv[] = {"doom", NULL};
        argv = fallback_argv;
        argc = 1;
    }

    if (!argv_has_iwad(argc, argv) && file_exists("/doom/doom1.wad")) {
        char **argv2 = calloc((size_t)argc + 3, sizeof(char *));
        if (argv2) {
            for (int i = 0; i < argc; i++) {
                argv2[i] = argv[i];
            }
            argv2[argc] = "-iwad";
            argv2[argc + 1] = "/doom/doom1.wad";
            argv2[argc + 2] = NULL;
            doomgeneric_Create(argc + 2, argv2);
        } else {
            doomgeneric_Create(argc, argv);
        }
    } else {
        doomgeneric_Create(argc, argv);
    }
    for (;;) {
        doomgeneric_Tick();
    }
    return 0;
}
