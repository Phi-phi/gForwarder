#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define CONFIG_FILE "config.txt"
#define MAX_LINE 1024
#define MAX_STR 128

struct nm_desc *nm_desc;

struct rule_dic {
  struct in_addr srcaddr;
  int srcport;
  struct in_addr dstaddr;
  char* priority;
}

struct rule_box {
  struct rule_dic *rule_dics[];
  size_t rule_num;
}

void printAllRules(struct rule_box *rules) {
  int i;
  char src[32], dst[32];
  struct rule_dic *rule_dics = rules->rule_dics;

  for (i = 0; i < rules->rule_num; ++i) {
    inet_ntop(AF_INET, rule_dics[i]->srcaddr, src, sizeof(src));
    inet_ntop(AF_INET, rule_dics[i]->dstaddr, dst, sizeof(dst));
    printf("\n------------\n");
    printf("src addr: %s\n", src);
    printf("src port: %d\n", rule_dics[i]->srcport);
    printf("dst addr: %s\n", dst);
    printf("priority: %s\n", rule_dics[i]->priority);
  }
}

void printHex(char* buf, size_t len) {
  int i;
  for(i = 0; i < len; ++i) {
    printf("%02X", ((unsigned char*)buf)[i]);
  }
  printf("\n");
}

void swapto(int to_hostring, struct netmap_slot *rxslot) {
  struct netmap_ring *txring;
  int i, first, last, sent = 0;;
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
  unsigned int r_cur, t_cur, i, t_i, is_hostring;
  int sent = 0, pktsizelen, conf_num = 0, idx = 0, rule_num = 0;
  char *buf, *payload, *tbuf;
  char conf_buf[MAX_STR];
  struct rule_box *rules;
  struct rule_dic *rule_dics[MAX_LINE];
  struct netmap_ring *rxring, *txring;
  struct pollfd pollfd[1];
  struct ether_header *ether;
  struct ether_arp *arp;
  struct ip *ip;
  struct udphdr *udp;
  FILE *conf;

  /* config file loading */
  if ((conf = fopen(CONFIG_FILE, "r")) == NULL) {
    printf("Config load error.\n");
    exit(-1);
  }

  while(fgets(conf_buf, MAX_LINE, conf) != NULL) {
    int line_len = strlen(conf_buf);
    int str_i, word_start_i = 0, rule_idx = 0;
    char rule_str[64];
    struct rule_dic *rule;
    for (str_i = 0; str_i < line_len; ++str_i) {
      if (strcmp(conf_buf[str_i], ' ')) {
        strncpy(rule_str, conf_buf + word_start_i, str_i - word_start_i);
        rule_str[str_i - word_start_i] = '\0';
        switch (rule_idx % 4) {
          case 0:
            rule->srcaddr.s_addr = inet_addr(rule_str);
            break;
          case 1:
            rule->srcport = atoi(rule_str);
            break;
          case 2:
            rule->dstaddr.s_addr = inet_addr(rule_str);
            break;
          case 3:
            rule->priority = rule_str;
            rule_dics[idx++] = rule;
            break;
        }
        ++rule_idx;
        word_start_i = str_i + 1;
      }
    }
    ++rule_num;
  }

  rules->rule_dics = rule_dics;
  rules->rule_num = rule_num;

  printAllRules(rules);

  nm_desc = nm_open("netmap:ix1*", NULL, 0, NULL);
  for(;;){
    pollfd[0].fd = nm_desc->fd;
    pollfd[0].events = POLLIN;
    poll(pollfd, 1, 100);

    for (i = nm_desc->first_rx_ring; i <= nm_desc->last_rx_ring; i++) {

      is_hostring = (i == nm_desc->last_rx_ring);

      rxring = NETMAP_RXRING(nm_desc->nifp, i);

      if(nm_ring_empty(rxring))
        continue;

      r_cur = rxring->cur;
      buf = NETMAP_BUF(rxring, rxring->slot[r_cur].buf_idx);
      pktsizelen = rxring->slot[r_cur].len;

      ether = (struct ether_header *)buf;

      if(ntohs(ether->ether_type) == ETHERTYPE_ARP) {
        printf("This is ARP.\n");
        arp = (struct ether_arp *)(buf + sizeof(struct ether_header));

        swapto(!is_hostring, &rxring->slot[r_cur]);
        rxring->head = rxring->cur = nm_ring_next(rxring, r_cur);
        continue;
      }
      ip = (struct ip *)(buf + sizeof(struct ether_header));
      payload = (char *)ip + (ip->ip_hl<<2);

      if (ip->ip_p == IPPROTO_UDP) {
        printHex(buf, pktsizelen);
        sent = 0;
        udp = (struct udphdr *)payload;
        change_ip_addr(buf, "10.2.2.2", "10.2.2.3", 11233);
        rxring->slot[r_cur].flags |= NS_BUF_CHANGED;

        for (t_i = nm_desc->first_tx_ring; t_i < nm_desc->last_tx_ring && !sent; ++t_i) {
          txring = NETMAP_TXRING(nm_desc->nifp, t_i);

          if (nm_ring_empty(txring))
            continue;

          t_cur = txring->cur;

          txring->slot[t_cur].buf_idx = rxring->slot[r_cur].buf_idx;
          txring->slot[t_cur].len = pktsizelen;
          txring->slot[t_cur].flags |= NS_BUF_CHANGED;

          txring->head = txring->cur = nm_ring_next(txring, t_cur);
          sent = 1;
          printf("ok.\n");
        }
      } else {
        if (ntohs(ether->ether_type) > 0) {
          swapto(!is_hostring, &rxring->slot[r_cur]);
        } else {
          printf("blank pkt\n");
          printHex(buf, pktsizelen);
        }
      }

      rxring->head = rxring->cur = nm_ring_next(rxring, r_cur);
    }
  }

  return 0;
}
