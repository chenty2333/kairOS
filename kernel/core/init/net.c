/**
 * kernel/core/init/net.c - Network initialization
 */

#include <kairos/net.h>
#include <kairos/socket.h>

void init_net(void) {
    net_init();
    af_unix_init();
    af_inet_init();
    lwip_net_init();
}
