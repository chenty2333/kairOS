/**
 * kernel/include/kairos/net.h - Minimal network device abstraction
 */

#ifndef _KAIROS_NET_H
#define _KAIROS_NET_H

#include <kairos/list.h>
#include <kairos/types.h>

struct netdev;

struct netdev_ops {
    int (*xmit)(struct netdev *dev, const void *data, size_t len);
};

struct netdev {
    char name[16];
    uint8_t mac[6];
    uint32_t mtu;
    const struct netdev_ops *ops;
    void *priv;
    struct list_head list;
};

void net_init(void);
int netdev_register(struct netdev *dev);
int netdev_unregister(struct netdev *dev);
struct netdev *netdev_first(void);

#endif
