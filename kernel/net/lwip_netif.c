/**
 * kernel/net/lwip_netif.c - Bridge between Kairos netdev and lwIP netif
 */

#include <kairos/mm.h>
#include <kairos/net.h>
#include <kairos/printk.h>
#include <kairos/string.h>

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/ip_addr.h"
#include "netif/ethernet.h"

static struct netif lwip_netif;
static struct netdev *lwip_netdev;

/* Called by lwIP to transmit a packet */
static err_t kairos_netif_output(struct netif *netif, struct pbuf *p) {
    struct netdev *dev = netif->state;
    if (!dev || !dev->ops || !dev->ops->xmit) {
        return ERR_IF;
    }

    /* Linearize pbuf chain into a contiguous buffer */
    uint8_t buf[2048];
    if (p->tot_len > sizeof(buf)) {
        return ERR_BUF;
    }

    size_t offset = 0;
    for (struct pbuf *q = p; q != NULL; q = q->next) {
        memcpy(buf + offset, q->payload, q->len);
        offset += q->len;
    }

    int ret = dev->ops->xmit(dev, buf, offset);
    return (ret == 0) ? ERR_OK : ERR_IF;
}

/* lwIP netif init callback */
static err_t kairos_netif_init(struct netif *netif) {
    struct netdev *dev = netif->state;

    netif->linkoutput = kairos_netif_output;
    netif->output = etharp_output;
    netif->mtu = dev->mtu;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    memcpy(netif->hwaddr, dev->mac, 6);
    netif->hwaddr_len = 6;

    netif->name[0] = 'e';
    netif->name[1] = 'n';

    return ERR_OK;
}

/**
 * Feed a received ethernet frame into lwIP.
 * Called from the network driver's RX interrupt handler.
 */
void lwip_netif_input(const void *data, size_t len) {
    if (!data || len == 0) {
        return;
    }

    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) {
        return;
    }

    /* Copy data into pbuf chain */
    size_t offset = 0;
    for (struct pbuf *q = p; q != NULL; q = q->next) {
        size_t n = (len - offset < q->len) ? (len - offset) : q->len;
        memcpy(q->payload, (const uint8_t *)data + offset, n);
        offset += n;
    }

    if (lwip_netif.input(p, &lwip_netif) != ERR_OK) {
        pbuf_free(p);
    }
}

/* tcpip_init completion callback */
static void lwip_init_done(void *arg) {
    (void)arg;
    pr_info("lwip: TCP/IP stack initialized\n");
}

/**
 * Initialize the lwIP stack and attach the first netdev.
 */
void lwip_net_init(void) {
    struct netdev *dev = netdev_first();
    if (!dev) {
        pr_info("lwip: no network device, skipping init\n");
        return;
    }

    lwip_netdev = dev;

    /* Start the tcpip thread and lwIP init */
    tcpip_init(lwip_init_done, NULL);

    /* Configure with DHCP */
    ip4_addr_t ip, mask, gw;
    ip4_addr_set_zero(&ip);
    ip4_addr_set_zero(&mask);
    ip4_addr_set_zero(&gw);

    LOCK_TCPIP_CORE();
    netif_add(&lwip_netif, &ip, &mask, &gw, dev,
              kairos_netif_init, tcpip_input);
    netif_set_default(&lwip_netif);
    netif_set_up(&lwip_netif);

    dhcp_start(&lwip_netif);
    UNLOCK_TCPIP_CORE();

    pr_info("lwip: attached to %s, DHCP started\n", dev->name);
}
