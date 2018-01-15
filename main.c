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
#include <signal.h>

#define CONFIG_FILE "config.txt"
#define MAX_LINE 1024
#define MAX_STR 128

static int caught_signal = 0;

struct nm_desc *nm_desc_rx, *nm_desc_tx;

struct rule_dic {
  struct in_addr srcaddr;
  int dstport;
  struct in_addr dstaddr;
  char* priority;
};

struct rule_box {
  struct rule_dic rule_dics[MAX_LINE];
  size_t rule_num;
};

void sigcatch(int sig) {
  if (sig == SIGINT) {
    printf("Ctrl-C interrupted\n");
    if (caught_signal) {
      printf("Double ctrl C -- exit.\n");
      exit(-1);
    }
    caught_signal = 1;
  }
}

void set_signal(int sig) {
  if (signal(sig, sigcatch) == SIG_ERR) {
    perror("signal");
    exit(-1);
  }
}

void printAllRules(struct rule_box *rules) {
  int i;
  char src[32], dst[32];
  struct rule_dic *rule_dics;

  rule_dics = rules->rule_dics;

  for (i = 0; i < rules->rule_num; ++i) {
    inet_ntop(AF_INET, &rule_dics[i].srcaddr, src, sizeof(src));
    inet_ntop(AF_INET, &rule_dics[i].dstaddr, dst, sizeof(dst));
    printf("\n------------\n");
    printf("src addr: %s\n", src);
    printf("src port: %d\n", rule_dics[i].dstport);
    printf("dst addr: %s\n", dst);
    printf("priority: %s\n", rule_dics[i].priority);
    printf("------------\n");
  }
}

void printHex(char* buf, size_t len) {
  int i;
  for(i = 0; i < len; ++i) {
    printf("%02X", ((unsigned char*)buf)[i]);
  }
  printf("\n");
}

void swapto(struct nm_desc *desc, int to_hostring, struct netmap_slot *rxslot) {
  struct netmap_ring *txring;
  int i, first, last, sent = 0;;
  uint32_t t, cur;

  if (to_hostring) {
#ifdef DEBUG
    fprintf(stderr, "NIC to HOST\n");
#endif
    first = last = desc->last_tx_ring;
  } else {
#ifdef DEBUG
    fprintf(stderr, "HOST to NIC\n");
#endif
    first = desc->first_tx_ring;
    last = desc->last_tx_ring - 1;
  }

  for (i = first; i <= last && !sent; ++i) {
    txring = NETMAP_TXRING(desc->nifp, i);
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

void change_ip_addr(char* pkt, struct in_addr dst) {
  struct ip *ip;
  struct ether_header *ether;
  struct udphdr *udp;

  ether = (struct ether_header *)pkt;
  ip = (struct ip *)(pkt + sizeof(struct ether_header));
  udp = (struct udphdr *)(pkt + sizeof(struct ether_header) + (ip->ip_hl<<2));

  //90:e2:ba:92:cb:d5
  ether->ether_shost[0] = 0x90;
  ether->ether_shost[1] = 0xe2;
  ether->ether_shost[2] = 0xba;
  ether->ether_shost[3] = 0x92;
  ether->ether_shost[4] = 0xcb;
  ether->ether_shost[5] = 0xd4;
  // 90:e2:ba:5d:8f:cd
  ether->ether_dhost[0] = 0x90;
  ether->ether_dhost[1] = 0xe2;
  ether->ether_dhost[2] = 0xba;
  ether->ether_dhost[3] = 0x5d;
  ether->ether_dhost[4] = 0x8f;
  ether->ether_dhost[5] = 0xcd;

  ip->ip_dst = dst;

  udp->uh_sum = 0;
}

int change_ip_by_rule(char* pkt, struct rule_box *rules) {
  int i, matched = 0;
  struct ip *ip;
  struct udphdr *udp;
  struct rule_dic *rule_dics = rules->rule_dics;

  ip = (struct ip *)(pkt + sizeof(struct ether_header));
  udp = (struct udphdr *)(pkt + sizeof(struct ether_header) + (ip->ip_hl<<2));

  for (i = 0; i < rules->rule_num; ++i) {
    if (ip->ip_src.s_addr == rule_dics[i].srcaddr.s_addr && ntohs(udp->uh_dport) == rule_dics[i].dstport) {
#ifdef DEBUG
      printf("match\n");
#endif
      change_ip_addr(pkt, rule_dics[i].dstaddr);
      matched = 1;
      break;
    }
  }

  return matched;
}

int main(int argc, char* argv[]) {
  unsigned int r_cur, t_cur, i, t_i, t_buf_i;
  int sent = 0, pktsizelen, idx = 0, rule_num = 0;
  unsigned int recv_num = 0, sent_num = 0;
  char *buf, *payload;
  char conf_buf[MAX_STR];
  struct rule_box *rules;
  struct rule_dic rule_dics[MAX_LINE];
  struct netmap_ring *rxring, *txring, *pending_txring;
  struct pollfd pollfd[2];
  struct ether_header *ether;
  struct ip *ip;
  FILE *conf;

  printf("OPTIONS:\n");
#ifdef DEBUG
  printf("DEBUG\n");
#endif
#ifdef ONLY_RECV
  printf("ONLY RECV\n");
#endif
#ifdef NOT_PENDING_TX
  printf("NOT PENDING TX\n");
#endif
  printf("-----------\n");

  /* config file loading */
  if ((conf = fopen(CONFIG_FILE, "r")) == NULL) {
    printf("Config load error.\n");
    exit(-1);
  }

  rules = (struct rule_box *)malloc(sizeof(struct rule_box));

  while(fgets(conf_buf, MAX_LINE, conf) != NULL) {
    int line_len = strlen(conf_buf);
    int str_i, word_start_i = 0, rule_idx = 0;
    char rule_str[64];
    struct rule_dic *rule = (struct rule_dic *)malloc(sizeof(struct rule_dic));
    for (str_i = 0; str_i < line_len; ++str_i) {
      if (conf_buf[str_i] == ' ' || conf_buf[str_i] == '\n' || conf_buf[str_i] == '\0') {
        strncpy(rule_str, conf_buf + word_start_i, str_i - word_start_i);
        rule_str[str_i - word_start_i] = '\0';
        switch (rule_idx) {
          case 0:
            rule->srcaddr.s_addr = inet_addr(rule_str);
            break;
          case 1:
            rule->dstport = atoi(rule_str);
            break;
          case 2:
            rule->dstaddr.s_addr = inet_addr(rule_str);
            break;
          case 3:
            rule->priority = rule_str;
            rule_dics[idx++] = *rule;
            break;
        }
        ++rule_idx;
        word_start_i = str_i + 1;
      }
    }
    ++rule_num;
  }

  memcpy(rules->rule_dics, rule_dics, sizeof(struct rule_dic) * (rule_num + 1));
  rules->rule_num = rule_num;

  printAllRules(rules);

  set_signal(SIGINT);

  nm_desc_rx = nm_open("netmap:ix1", NULL, 0, NULL);
  nm_desc_tx = nm_open("netmap:ix0", NULL, NM_OPEN_NO_MMAP, nm_desc_rx);
  pollfd[0].fd = nm_desc_rx->fd;
  pollfd[0].events = POLLIN;
  pollfd[1].fd = nm_desc_tx->fd;
  pollfd[1].events = POLLOUT;

  printf("Ready.\n");

  for (;;) {
    poll(pollfd, 2, 3000);

    for (i = nm_desc_rx->first_rx_ring; i <= nm_desc_rx->last_rx_ring && !caught_signal; i++) {

      rxring = NETMAP_RXRING(nm_desc_rx->nifp, i);

      while(!nm_ring_empty(rxring) && !caught_signal) {

        r_cur = rxring->cur;
        buf = NETMAP_BUF(rxring, rxring->slot[r_cur].buf_idx);
        pktsizelen = rxring->slot[r_cur].len;

        ether = (struct ether_header *)buf;

        if(ntohs(ether->ether_type) == ETHERTYPE_ARP) {
          rxring->head = rxring->cur = nm_ring_next(rxring, r_cur);
          continue;
        }
        ip = (struct ip *)(buf + sizeof(struct ether_header));
        payload = (char *)ip + (ip->ip_hl<<2);

        if (ip->ip_p == IPPROTO_UDP) {
#ifdef DEBUG
          printHex(buf, pktsizelen);
#endif
          ++recv_num;
          sent = 0;
#ifndef ONLY_RECV
          if (change_ip_by_rule(buf, rules)) {
            for (t_i = nm_desc_tx->first_tx_ring; t_i <= nm_desc_tx->last_tx_ring; ++t_i) {
              txring = NETMAP_TXRING(nm_desc_tx->nifp, t_i);

              if (nm_ring_empty(txring)) {
#ifndef NOT_PENDING_TX
                if (t_i == nm_desc_tx->last_tx_ring) {
                  pending_txring = NETMAP_TXRING(nm_desc_tx->nifp, nm_desc_tx->first_tx_ring);
                  while(nm_tx_pending(pending_txring)) {
                    ioctl(nm_desc_tx->fd, NIOCTXSYNC, NULL);
                  }
                }  
#endif
                continue;
              }

              t_cur = txring->cur;

              t_buf_i = txring->slot[t_cur].buf_idx;

              txring->slot[t_cur].buf_idx = rxring->slot[r_cur].buf_idx;
              txring->slot[t_cur].len = pktsizelen;
              txring->slot[t_cur].flags |= NS_BUF_CHANGED;

              rxring->slot[r_cur].buf_idx = t_buf_i;
              rxring->slot[r_cur].flags = NS_BUF_CHANGED;

              txring->head = txring->cur = nm_ring_next(txring, t_cur);
              sent = 1;
              ++sent_num;
              break;
#ifdef DEBUG
              printf("ok.\n");
#endif
            }
          }
#endif
        }

        rxring->head = rxring->cur = nm_ring_next(rxring, r_cur);
      }
    }

    if (caught_signal) {
#ifndef ONLY_RECV
      while(nm_tx_pending(txring)) {
        ioctl(nm_desc_tx->fd, NIOCTXSYNC, NULL);
      }
#endif
      printf("finish.\n");
      printf("Recv: %d\nSent: %d\n", recv_num, sent_num);
      sleep(2);
      break;
    }
  }

  free(rules);
  nm_close(nm_desc_rx);
  nm_close(nm_desc_tx);
  return 0;
}
