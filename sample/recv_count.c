#include <poll.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

struct nm_desc *nm_desc;

void printHex(char* buf, size_t len) {
  int i;
  for(i = 0; i < len; ++i) {
    printf("%02X", ((unsigned char*)buf)[i]);
  }
  printf("\n");
}

void swapto(int to_hostring, struct netmap_slot *rxslot) {
  struct netmap_ring *txring;
  int i, first, last;
  uint32_t t, cur;

  if (to_hostring) {
#ifdef DEBUG
    fprintf(stderr, "NIC to HOST\n");
#endif
    first = last = nm_desc->last_tx_ring;
  } else {
#ifdef DEBUG
    fprintf(stderr, "HOST to NIC\n");
#endif
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

int main(int argc, char* argv[]) {
  unsigned int cur, i, is_hostring, bi, recv_num = 0;
  char *buf, *payload;
  struct netmap_ring *rxring;
  struct pollfd pollfd[1];
  struct ether_header *ether;
  struct ip *ip;

  nm_desc = nm_open("netmap:ix0*", NULL, 0, NULL);
  printf("counting udp\n");
  printf("%9d",0);
  fflush(stdout);
  for(;;){
    pollfd[0].fd = nm_desc->fd;
    pollfd[0].events = POLLIN;
    poll(pollfd, 1, -1);

    for (i = nm_desc->first_rx_ring; i <= nm_desc->last_rx_ring; i++) {

      is_hostring = (i == nm_desc->last_rx_ring);

      rxring = NETMAP_RXRING(nm_desc->nifp, i);

      while(!nm_ring_empty(rxring)) {
        cur = rxring->cur;
        buf = NETMAP_BUF(rxring, rxring->slot[cur].buf_idx);
        ether = (struct ether_header *)buf;
        if(ntohs(ether->ether_type) == ETHERTYPE_ARP) {
          swapto(!is_hostring, &rxring->slot[cur]);
          rxring->head = rxring->cur = nm_ring_next(rxring, cur);
          continue;
        }
        ip = (struct ip *)(buf + sizeof(struct ether_header));
        payload = (char *)ip + (ip->ip_hl<<2);

        if (ip->ip_p == IPPROTO_UDP) {
          ++recv_num;
        }

        swapto(!is_hostring, &rxring->slot[cur]);
        rxring->head = rxring->cur = nm_ring_next(rxring, cur);
      }
    }
    for (bi = 0; bi < 9; ++bi) {
      printf("\b");
    }
    printf("%9d", recv_num);
    fflush(stdout);
    if (ioctl(nm_desc->fd, NIOCRXSYNC, NULL) != 0)
      perror("sync ioctl");
  }
  return 0;
}
