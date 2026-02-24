/**
 * kernel/net/net_ioctl.c - Network ioctl handler
 *
 * Handles SIOC* network ioctls for ifconfig/route support.
 * Reads/writes lwIP netif state for addr/netmask/flags.
 */

#include <kairos/ioctl.h>
#include <kairos/mm.h>
#include <kairos/net.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>

#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"

/* AF_INET from socket headers */
#define AF_INET 2

/* Linux interface flags */
#define IFF_UP          0x1
#define IFF_BROADCAST   0x2
#define IFF_LOOPBACK    0x8
#define IFF_RUNNING     0x40
#define IFF_MULTICAST   0x1000

static struct netif *find_lwip_netif(void) {
    /* Walk the lwIP netif list */
    struct netif *nif;
    NETIF_FOREACH(nif) {
        return nif;
    }
    return NULL;
}

static struct netdev *find_netdev_by_name(const char *name) {
    struct netdev *dev = netdev_first();
    if (!dev)
        return NULL;
    /* For now we only have one device; check if name matches */
    if (strncmp(dev->name, name, IFNAMSIZ) == 0) {
        return dev;
    }
    /* Also match "eth0" which ifconfig may use */
    if (strncmp(name, "eth0", IFNAMSIZ) == 0) {
        return dev;
    }
    return NULL;
}

static void sockaddr_from_ip4(struct sockaddr_kairos *sa, uint32_t ip) {
    memset(sa, 0, sizeof(*sa));
    sa->sa_family = AF_INET;
    /* Network byte order IP in sa_data[2..5] */
    sa->sa_data[2] = (char)(ip & 0xff);
    sa->sa_data[3] = (char)((ip >> 8) & 0xff);
    sa->sa_data[4] = (char)((ip >> 16) & 0xff);
    sa->sa_data[5] = (char)((ip >> 24) & 0xff);
}

static uint32_t ip4_from_sockaddr(const struct sockaddr_kairos *sa) {
    return (uint32_t)(uint8_t)sa->sa_data[2] |
           ((uint32_t)(uint8_t)sa->sa_data[3] << 8) |
           ((uint32_t)(uint8_t)sa->sa_data[4] << 16) |
           ((uint32_t)(uint8_t)sa->sa_data[5] << 24);
}

int net_ioctl(struct file *f __attribute__((unused)),
              uint32_t cmd, uint64_t arg) {
    struct ifreq ifr;

    if (!arg)
        return -EFAULT;

    switch (cmd) {
    case SIOCGIFCONF: {
        struct ifconf ifc;
        if (copy_from_user(&ifc, (void *)arg, sizeof(ifc)) < 0)
            return -EFAULT;

        struct netdev *dev = netdev_first();
        if (!dev || ifc.ifc_len < (int)sizeof(struct ifreq)) {
            ifc.ifc_len = 0;
            if (copy_to_user((void *)arg, &ifc, sizeof(ifc)) < 0)
                return -EFAULT;
            return 0;
        }

        struct ifreq resp;
        memset(&resp, 0, sizeof(resp));
        strncpy(resp.ifr_name, dev->name, IFNAMSIZ - 1);

        struct netif *nif = find_lwip_netif();
        if (nif) {
            LOCK_TCPIP_CORE();
            sockaddr_from_ip4(&resp.ifr_addr, ip_addr_get_ip4_u32(&nif->ip_addr));
            UNLOCK_TCPIP_CORE();
        }

        if (copy_to_user(ifc.ifc_req, &resp, sizeof(resp)) < 0)
            return -EFAULT;
        ifc.ifc_len = sizeof(struct ifreq);
        if (copy_to_user((void *)arg, &ifc, sizeof(ifc)) < 0)
            return -EFAULT;
        return 0;
    }

    case SIOCGIFFLAGS: {
        if (copy_from_user(&ifr, (void *)arg, sizeof(ifr)) < 0)
            return -EFAULT;
        struct netdev *dev = find_netdev_by_name(ifr.ifr_name);
        if (!dev)
            return -ENODEV;

        short flags = IFF_BROADCAST | IFF_MULTICAST;
        struct netif *nif = find_lwip_netif();
        if (nif) {
            LOCK_TCPIP_CORE();
            if (nif->flags & NETIF_FLAG_UP) {
                flags |= IFF_UP | IFF_RUNNING;
            }
            UNLOCK_TCPIP_CORE();
        }
        ifr.ifr_flags = flags;
        if (copy_to_user((void *)arg, &ifr, sizeof(ifr)) < 0)
            return -EFAULT;
        return 0;
    }

    case SIOCSIFFLAGS: {
        if (copy_from_user(&ifr, (void *)arg, sizeof(ifr)) < 0)
            return -EFAULT;
        struct netif *nif = find_lwip_netif();
        if (!nif)
            return -ENODEV;
        LOCK_TCPIP_CORE();
        if (ifr.ifr_flags & IFF_UP) {
            netif_set_up(nif);
        } else {
            netif_set_down(nif);
        }
        UNLOCK_TCPIP_CORE();
        return 0;
    }

    case SIOCGIFADDR: {
        if (copy_from_user(&ifr, (void *)arg, sizeof(ifr)) < 0)
            return -EFAULT;
        struct netdev *dev = find_netdev_by_name(ifr.ifr_name);
        if (!dev)
            return -ENODEV;
        struct netif *nif = find_lwip_netif();
        if (!nif)
            return -ENODEV;
        LOCK_TCPIP_CORE();
        sockaddr_from_ip4(&ifr.ifr_addr, ip_addr_get_ip4_u32(&nif->ip_addr));
        UNLOCK_TCPIP_CORE();
        if (copy_to_user((void *)arg, &ifr, sizeof(ifr)) < 0)
            return -EFAULT;
        return 0;
    }

    case SIOCSIFADDR: {
        if (copy_from_user(&ifr, (void *)arg, sizeof(ifr)) < 0)
            return -EFAULT;
        struct netif *nif = find_lwip_netif();
        if (!nif)
            return -ENODEV;
        ip4_addr_t addr;
        addr.addr = ip4_from_sockaddr(&ifr.ifr_addr);
        LOCK_TCPIP_CORE();
        netif_set_ipaddr(nif, &addr);
        UNLOCK_TCPIP_CORE();
        return 0;
    }

    case SIOCGIFNETMASK: {
        if (copy_from_user(&ifr, (void *)arg, sizeof(ifr)) < 0)
            return -EFAULT;
        struct netdev *dev = find_netdev_by_name(ifr.ifr_name);
        if (!dev)
            return -ENODEV;
        struct netif *nif = find_lwip_netif();
        if (!nif)
            return -ENODEV;
        LOCK_TCPIP_CORE();
        sockaddr_from_ip4(&ifr.ifr_netmask, ip_addr_get_ip4_u32(&nif->netmask));
        UNLOCK_TCPIP_CORE();
        if (copy_to_user((void *)arg, &ifr, sizeof(ifr)) < 0)
            return -EFAULT;
        return 0;
    }

    case SIOCSIFNETMASK: {
        if (copy_from_user(&ifr, (void *)arg, sizeof(ifr)) < 0)
            return -EFAULT;
        struct netif *nif = find_lwip_netif();
        if (!nif)
            return -ENODEV;
        ip4_addr_t mask;
        mask.addr = ip4_from_sockaddr(&ifr.ifr_netmask);
        LOCK_TCPIP_CORE();
        netif_set_netmask(nif, &mask);
        UNLOCK_TCPIP_CORE();
        return 0;
    }

    case SIOCGIFHWADDR: {
        if (copy_from_user(&ifr, (void *)arg, sizeof(ifr)) < 0)
            return -EFAULT;
        struct netdev *dev = find_netdev_by_name(ifr.ifr_name);
        if (!dev)
            return -ENODEV;
        memset(&ifr.ifr_hwaddr, 0, sizeof(ifr.ifr_hwaddr));
        ifr.ifr_hwaddr.sa_family = 1; /* ARPHRD_ETHER */
        memcpy(ifr.ifr_hwaddr.sa_data, dev->mac, 6);
        if (copy_to_user((void *)arg, &ifr, sizeof(ifr)) < 0)
            return -EFAULT;
        return 0;
    }

    case SIOCGIFMTU: {
        if (copy_from_user(&ifr, (void *)arg, sizeof(ifr)) < 0)
            return -EFAULT;
        struct netdev *dev = find_netdev_by_name(ifr.ifr_name);
        if (!dev)
            return -ENODEV;
        ifr.ifr_mtu = (int)dev->mtu;
        if (copy_to_user((void *)arg, &ifr, sizeof(ifr)) < 0)
            return -EFAULT;
        return 0;
    }

    case SIOCSIFMTU: {
        if (copy_from_user(&ifr, (void *)arg, sizeof(ifr)) < 0)
            return -EFAULT;
        struct netdev *dev = find_netdev_by_name(ifr.ifr_name);
        if (!dev)
            return -ENODEV;
        dev->mtu = (uint32_t)ifr.ifr_mtu;
        struct netif *nif = find_lwip_netif();
        if (nif) {
            LOCK_TCPIP_CORE();
            nif->mtu = (u16_t)dev->mtu;
            UNLOCK_TCPIP_CORE();
        }
        return 0;
    }

    case SIOCADDRT:
    case SIOCDELRT:
        return -ENOSYS;

    default:
        return -ENOTTY;
    }
}
