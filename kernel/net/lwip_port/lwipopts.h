/**
 * lwipopts.h - lwIP configuration for Kairos kernel
 */

#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* --- Threading model --- */
#define NO_SYS                  0
#define LWIP_TCPIP_CORE_LOCKING 1
#define SYS_LIGHTWEIGHT_PROT    1

/* --- Memory --- */
#define MEM_ALIGNMENT           8
#define MEM_SIZE                (64 * 1024)
#define MEMP_NUM_PBUF           32
#define MEMP_NUM_UDP_PCB        8
#define MEMP_NUM_TCP_PCB        16
#define MEMP_NUM_TCP_PCB_LISTEN 4
#define MEMP_NUM_TCP_SEG        32
#define MEMP_NUM_SYS_TIMEOUT    16
#define PBUF_POOL_SIZE          32
#define PBUF_POOL_BUFSIZE       1536

/* Use kernel allocator for MEM_LIBC_MALLOC */
#define MEM_LIBC_MALLOC         0

/* --- TCP --- */
#define LWIP_TCP                1
#define TCP_MSS                 1460
#define TCP_WND                 (8 * TCP_MSS)
#define TCP_SND_BUF             (8 * TCP_MSS)
#define TCP_SND_QUEUELEN        (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_LISTEN_BACKLOG      1

/* --- UDP --- */
#define LWIP_UDP                1

/* --- IP --- */
#define LWIP_IPV4               1
#define LWIP_IPV6               0
#define LWIP_ICMP               1
#define LWIP_RAW                0
#define LWIP_IGMP               0

/* --- DHCP --- */
#define LWIP_DHCP               1
#define LWIP_AUTOIP             0
#define LWIP_ACD                0
#define LWIP_DHCP_DOES_ACD_CHECK 0

/* --- ARP --- */
#define LWIP_ARP                1
#define ARP_TABLE_SIZE          10
#define ARP_QUEUEING            1
#define ETHARP_SUPPORT_STATIC_ENTRIES 0

/* --- DNS --- */
#define LWIP_DNS                0

/* --- Socket/Netconn API --- */
/* We use raw API only; our own socket layer wraps it */
#define LWIP_SOCKET             0
#define LWIP_NETCONN            0
#define LWIP_CALLBACK_API       1

/* --- Netif --- */
#define LWIP_NETIF_HOSTNAME     0
#define LWIP_NETIF_API          0
#define LWIP_NETIF_LOOPBACK     1

/* --- Stats --- */
#define LWIP_STATS              0
#define LWIP_STATS_DISPLAY      0

/* --- Debugging --- */
#define LWIP_DEBUG              0
#define LWIP_DBG_TYPES_ON       LWIP_DBG_OFF
#define ETHARP_DEBUG            LWIP_DBG_OFF
#define NETIF_DEBUG             LWIP_DBG_OFF
#define PBUF_DEBUG              LWIP_DBG_OFF
#define API_LIB_DEBUG           LWIP_DBG_OFF
#define API_MSG_DEBUG           LWIP_DBG_OFF
#define SOCKETS_DEBUG           LWIP_DBG_OFF
#define ICMP_DEBUG              LWIP_DBG_OFF
#define IGMP_DEBUG              LWIP_DBG_OFF
#define INET_DEBUG              LWIP_DBG_OFF
#define IP_DEBUG                LWIP_DBG_OFF
#define IP_REASS_DEBUG          LWIP_DBG_OFF
#define RAW_DEBUG               LWIP_DBG_OFF
#define MEM_DEBUG               LWIP_DBG_OFF
#define MEMP_DEBUG              LWIP_DBG_OFF
#define SYS_DEBUG               LWIP_DBG_OFF
#define TIMERS_DEBUG            LWIP_DBG_OFF
#define TCP_DEBUG               LWIP_DBG_OFF
#define TCP_INPUT_DEBUG         LWIP_DBG_OFF
#define TCP_FR_DEBUG            LWIP_DBG_OFF
#define TCP_RTO_DEBUG           LWIP_DBG_OFF
#define TCP_CWND_DEBUG          LWIP_DBG_OFF
#define TCP_WND_DEBUG           LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG        LWIP_DBG_OFF
#define TCP_RST_DEBUG           LWIP_DBG_OFF
#define TCP_QLEN_DEBUG          LWIP_DBG_OFF
#define UDP_DEBUG               LWIP_DBG_OFF
#define TCPIP_DEBUG             LWIP_DBG_OFF
#define DHCP_DEBUG              LWIP_DBG_OFF

/* --- Checksum --- */
#define CHECKSUM_GEN_IP         1
#define CHECKSUM_GEN_UDP        1
#define CHECKSUM_GEN_TCP        1
#define CHECKSUM_GEN_ICMP       1
#define CHECKSUM_CHECK_IP       1
#define CHECKSUM_CHECK_UDP      1
#define CHECKSUM_CHECK_TCP      1
#define CHECKSUM_CHECK_ICMP     1

/* --- Misc --- */
#define LWIP_PROVIDE_ERRNO      0
#define LWIP_ERRNO_STDINCLUDE   0

#endif /* LWIPOPTS_H */
