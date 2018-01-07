#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>

struct nm_desc *nm_desc;

void swapto(int to_hostring, struct netmap_slot *rxslot) {
  struct netmap_ring *txring;
  int i, first, last;
  uint32_t t, cur;

  if (to_hostring) {
    fprintf(stderr, "NIC to HOST\n");
    first = last = nm_desc->last_tx_ring;
  } else {
    fprintf(stderr, "HOST to NIC\n");
    first = nm_desc->first_tx_ring;
    last = nm_desc->last_tx_ring - 1;
  }

  for (i = first; i <= last; ++i) {
    txring = NETMAP_TXRING(nm_desc->nifp, i);
    while(!nm_ring_empty(txring)) {
      cur = txring->cur;

      t = txring->slot[cur].buf_idx;
      txring->slot[cur].buf_idx = rxslot->buf_idx;
      rxslot->buf_idx = t;

      txring->slot[cur].len = rxslot->len;

      txring->slot[cur].flags |= NS_BUF_CHANGED;
      rxslot->flags |= NS_BUF_CHANGED;

      txring->head = txring->cur = nm_ring_next(txring, cur);

      break;
    }
  }
}

void change_ip_addr(char* pkt, const char* new_src, const char* new_dst, int dst_port) {
  struct ip *ip;
  struct udphdr *udp;
  struct in_addr src, dst;

  src.s_addr = inet_addr(new_src);
  dst.s_addr = inet_addr(new_dst);

  ip = (struct ip *)(pkt + sizeof(struct ether_header));
  udp = (struct udphdr *)(ip + (ip->ip_hl<<2));

  ip->ip_src = src;
  ip->ip_dst = dst;

  udp->uh_sport = htons(65001);
  udp->uh_dport = htons(dst_port);
}

int main(int argc, char* argv[]) {
  unsigned int cur, i, t_i, is_hostring, recieved;
  int sent = 0, pktsizelen;
  char *buf, *payload, *tbuf;
  struct netmap_ring *rxring, *txring;
  struct pollfd pollfd[1];
  struct ether_header *ether;
  struct ether_arp *arp;
  struct ip *ip;
  struct udphdr *udp;

  nm_desc = nm_open("netmap:ix1*", NULL, 0, NULL);
  for(;;){
    pollfd[0].fd = nm_desc->fd;
    pollfd[0].events = POLLIN | POLLOUT;
    poll(pollfd, 1, 100);

    recieved = 0;

    for (i = nm_desc->first_rx_ring; i <= nm_desc->last_rx_ring; i++) {

      is_hostring = (i == nm_desc->last_rx_ring);

      rxring = NETMAP_RXRING(nm_desc->nifp, i);

      while(!nm_ring_empty(rxring)) {
        recieved = 1;
        cur = rxring->cur;
        buf = NETMAP_BUF(rxring, rxring->slot[cur].buf_idx);
        pktsizelen = rxring->slot[cur].len;
        ether = (struct ether_header *)buf;
        if(ntohs(ether->ether_type) == ETHERTYPE_ARP) {
          printf("This is ARP.\n");
          arp = (struct ether_arp *)(buf + sizeof(struct ether_header));

          swapto(!is_hostring, &rxring->slot[cur]);
          rxring->head = rxring->cur = nm_ring_next(rxring, cur);
          continue;
        }
        ip = (struct ip *)(buf + sizeof(struct ether_header));
        payload = (char *)ip + (ip->ip_hl<<2);

        if (ip->ip_p == IPPROTO_UDP) {
          sent = 0;
          udp = (struct udphdr *)payload;
          change_ip_addr(buf, "10.2.2.2", "10.2.2.3", 11233);

          for (t_i = nm_desc->first_tx_ring; t_i < nm_desc->last_tx_ring || sent; ++t_i) {
            txring = NETMAP_TXRING(nm_desc->nifp, t_i);

            if (nm_ring_empty(txring))
              continue;

            cur = txring->cur;

            tbuf = NETMAP_BUF(txring, txring->slot[cur].buf_idx);

            nm_pkt_copy(buf, tbuf, pktsizelen);
            txring->slot[cur].len = pktsizelen;
            txring->slot[cur].flags |= NS_BUF_CHANGED;

            txring->head = txring->cur = nm_ring_next(txring, cur);
            sent = 1;

            while(nm_tx_pending(txring)) {
              ioctl(nm_desc->fd, NIOCTXSYNC, NULL);
            }
          }
        }

        swapto(!is_hostring, &rxring->slot[cur]);
        rxring->head = rxring->cur = nm_ring_next(rxring, cur);
      }
    }
  }

  return 0;
}
