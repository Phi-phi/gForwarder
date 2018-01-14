/*
   read NetFlow pcap file and sending
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pcap.h>

struct nm_desc *nm_desc;

void swapto(int to_hostring, struct netmap_slot *rxslot) {
  struct netmap_ring *txring;
  int i, first, last, sent = 0;
  uint32_t t, cur;

  if (to_hostring) {
    fprintf(stderr, "NIC to HOST\n");
    first = last = nm_desc->last_tx_ring;
  } else {
    fprintf(stderr, "HOST to NIC\n");
    first = nm_desc->first_tx_ring;
    last = nm_desc->last_tx_ring - 1;
  }

  for (i = first; i <= last && !sent; ++i) {
    txring = NETMAP_TXRING(nm_desc->nifp, i);
    while(!nm_ring_empty(txring)) {
      cur = txring->cur;

      if (txring->slot[cur].flags & NS_BUF_CHANGED) {
        // this slot has already changed
        txring->head = txring->cur = nm_ring_next(txring, cur);
        continue;
      }
      t = txring->slot[cur].buf_idx;
      txring->slot[cur].buf_idx = rxslot->buf_idx;
      rxslot->buf_idx = t;

      txring->slot[cur].len = rxslot->len;

      txring->slot[cur].flags |= NS_BUF_CHANGED;
      rxslot->flags |= NS_BUF_CHANGED;

      sent = 1;
      txring->head = txring->cur = nm_ring_next(txring, cur);

      break;
    }
  }
}

void change_ip_addr(char* pkt, const char *dst_addr) {
  struct ip *ip;
  struct ether_header *ether;
  struct udphdr *udp;
  struct in_addr src, dst;

  src.s_addr = inet_addr("10.2.2.6");
  dst.s_addr = inet_addr(dst_addr);

  ether = (struct ether_header *)pkt;
  ip = (struct ip *)(pkt + sizeof(struct ether_header));
  udp = (struct udphdr *)(pkt + sizeof(struct ether_header) + (ip->ip_hl<<2));

  //90:e2:ba:92:cb:d5
  ether->ether_shost[0] = 0x90;
  ether->ether_shost[1] = 0xe2;
  ether->ether_shost[2] = 0xba;
  ether->ether_shost[3] = 0x92;
  ether->ether_shost[4] = 0xcb;
  ether->ether_shost[5] = 0xd5;
  // 90:e2:ba:5d:8f:cd
  ether->ether_dhost[0] = 0x90;
  ether->ether_dhost[1] = 0xe2;
  ether->ether_dhost[2] = 0xba;
  ether->ether_dhost[3] = 0x5d;
  ether->ether_dhost[4] = 0x8f;
  ether->ether_dhost[5] = 0xcd;

  ip->ip_src = src;
  ip->ip_dst = dst;

  udp->uh_dport = htons(9996);
  udp->uh_sum = 0;
}

void swap_udp_port(char* pkt) {
  struct ip *ip;
  struct udphdr *udp;

  ip = (struct ip *)(pkt + sizeof(struct ether_header));
  udp = (struct udphdr *)(pkt + sizeof(struct ether_header) + (ip->ip_hl<<2));

  if (ntohs(udp->uh_dport) == 9996) {
    udp->uh_dport = htons(8081);
  } else {
    udp->uh_sport = htons(9996);
  }
}

int main(int argc, char* argv[]) {
  int pktsizelen, sent = 0, send_num, eternal = 0;
  unsigned int cur, i;
  char *errbuf = NULL;
  const u_char* r_pkt;
  pcap_t *pcap;
  char *pkt, *pkt2, *buf;
  struct pcap_pkthdr *header = NULL;
  struct netmap_ring *txring;
  struct pollfd pollfd[1];

  send_num = atoi(argv[1]);
  if (send_num == 0) {
    eternal = 1;
  } else if (send_num < 0) {
    printf("send num error.\n");
    exit(-1);
  }

  // prepare for packet
  pcap = pcap_open_offline("netflow-pcap.pcap", errbuf);

  if (pcap == NULL) {
    printf("pcap load fail.\n");
    exit(-1);
  }

  pcap_next_ex(pcap, &header, &r_pkt);

  pktsizelen = header->len;

  pkt = (char*)malloc(pktsizelen);
  pkt2 = (char*)malloc(pktsizelen);

  memcpy(pkt, r_pkt, pktsizelen);

  change_ip_addr(pkt, "10.2.2.2");
  strcpy(pkt2, (const char*)r_pkt);
  swap_udp_port(pkt2);

  nm_desc = nm_open("netmap:ix1", NULL, 0, NULL);

  ioctl(nm_desc->fd, NIOCTXSYNC, NULL);

  pollfd[0].fd = nm_desc->fd;
  pollfd[0].events = POLLOUT;

  while (1) {
    poll(pollfd, 1, -1);

    while (eternal || sent < send_num) {
      for (i = nm_desc->first_tx_ring; i<= nm_desc->last_tx_ring && (eternal || sent < send_num); ++i) {
        txring = NETMAP_TXRING(nm_desc->nifp, i);

        while(!nm_ring_empty(txring) && (sent < send_num || eternal)) {
          cur = txring->cur;

          buf = NETMAP_BUF(txring, txring->slot[cur].buf_idx);
          nm_pkt_copy(pkt, buf, pktsizelen);
          txring->slot[cur].len = pktsizelen;
          txring->slot[cur].flags |= NS_BUF_CHANGED;

          txring->head = txring->cur = nm_ring_next(txring, cur);
          ++sent;
        }

        while(nm_tx_pending(txring)) {
          ioctl(nm_desc->fd, NIOCTXSYNC, NULL);
        }
      }
    }
  }

  nm_close(nm_desc);
  return 0;
}
