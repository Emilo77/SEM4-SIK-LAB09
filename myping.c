#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
// this sets ICMP declaration
#include <netinet/ip_icmp.h>

#include "common.h"

#define BSIZE 1000
#define ICMP_HEADER_LEN 8
#define ICMP_PACKAGE_LEN 28

#define MAX_ID 1 << 1

bool finish = false;
uint16_t seq_num = 0;

struct ping_info {
  ssize_t len;             // git
  struct sockaddr_in addr; // git
  int ttl;
  uint16_t seq;
  float timestamp;
};

/* Obsługa sygnału kończenia */
static void catch_int(int sig) {
  if (finish == true) {
    exit(1);
  }
  finish = true;
  fprintf(stderr, " Signal %d catched. Ping closing.\n", sig);
}

void send_ping_request(int sock, char *s_send_addr) {
  struct addrinfo addr_hints;
  struct addrinfo *addr_result;
  struct sockaddr_in send_addr;
  struct icmp *icmp;

  char send_buffer[BSIZE];

  int err;
  int icmp_len;
  ssize_t len;

  // 'converting' host/port in string to struct addrinfo
  memset(&addr_hints, 0, sizeof(struct addrinfo));
  addr_hints.ai_family = AF_INET;
  addr_hints.ai_socktype = SOCK_RAW;
  addr_hints.ai_protocol = IPPROTO_ICMP;
  err = getaddrinfo(s_send_addr, 0, &addr_hints, &addr_result);
  if (err != 0)
    syserr("getaddrinfo: %s\n", gai_strerror(err));

  send_addr.sin_family = AF_INET;
  send_addr.sin_addr.s_addr =
      ((struct sockaddr_in *)(addr_result->ai_addr))->sin_addr.s_addr;
  send_addr.sin_port = htons(0);
  freeaddrinfo(addr_result);

  memset(send_buffer, 0, sizeof(send_buffer));
  // initializing ICMP header
  icmp = (struct icmp *)send_buffer;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_id = htons(getpid() % MAX_ID); // process identified by PID
  // modulo MAX_ID in case pid is greater than 2^16
  icmp->icmp_seq = htons((uint16_t)seq_num++); // sequential number

  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
    syserr("clock_gettime");
  memcpy(send_buffer + ICMP_HEADER_LEN, &start, sizeof(struct timespec));
  icmp_len =
      sizeof(struct timespec) + ICMP_HEADER_LEN; // packet is filled with 0
  icmp->icmp_cksum = 0; // checksum computed over whole ICMP package
  icmp->icmp_cksum = in_cksum((unsigned short *)icmp, icmp_len);

  len = sendto(sock, send_buffer, icmp_len, 0, (struct sockaddr *)&send_addr,
               (socklen_t)sizeof(send_addr));

  if (icmp_len != (ssize_t)len)
    syserr("partial / failed write");
}

int receive_ping_reply(int sock, struct ping_info *info) {
  struct sockaddr_in rcv_addr;
  socklen_t rcv_addr_len;

  struct ip *ip;
  struct icmp *icmp;

  char rcv_buffer[BSIZE];

  ssize_t ip_header_len;
  ssize_t icmp_len;
  ssize_t len;

  memset(rcv_buffer, 0, sizeof(rcv_buffer));
  rcv_addr_len = (socklen_t)sizeof(rcv_addr);
  len = recvfrom(sock, rcv_buffer, sizeof(rcv_buffer), 0,
                 (struct sockaddr *)&rcv_addr, &rcv_addr_len);
  if (len == -1)
    syserr("failed read");

  struct timespec end;
  if (clock_gettime(CLOCK_MONOTONIC, &end) == -1)
    syserr("clock_gettime");

  struct timespec start;
  memset(&start, 0, sizeof(struct timespec));
  memcpy(&start, rcv_buffer + ICMP_PACKAGE_LEN, sizeof(struct timespec));

  info->timestamp = (end.tv_sec - start.tv_sec) * 1000 +
                    (float)(end.tv_nsec - start.tv_nsec) / 1e6;
  info->addr = rcv_addr;
  info->len = len;

  ip = (struct ip *)rcv_buffer;
  ip_header_len = ip->ip_hl << 2; // IP header len is in 4-byte words
  info->ttl = ip->ip_ttl;

  icmp = (struct icmp *)(rcv_buffer + ip_header_len); // ICMP header follows IP
  icmp_len = len - ip_header_len;
  info->seq = icmp->icmp_seq;

  if (icmp_len < ICMP_HEADER_LEN)
    fatal("icmp header len (%d) < ICMP_HEADER_LEN", icmp_len);

  if (icmp->icmp_type != ICMP_ECHOREPLY) {
    printf("strange reply type (%d)\n", icmp->icmp_type);
    return 0;
  }

  if (ntohs(icmp->icmp_id) != getpid() % MAX_ID)
    fatal("reply with id %d different from my pid %d", ntohs(icmp->icmp_id),
          getpid());

  return 1;
}

void print_info(struct ping_info info) {
  printf("%zu bytes from %s: ", info.len, inet_ntoa(info.addr.sin_addr));
  printf("icmp_seq=%d ttl=%d", ntohs(info.seq), info.ttl);
  printf(" time=%0.3f ms\n", info.timestamp);
}

int main(int argc, char *argv[]) {
  int sock;

  if (argc < 2) {
    fatal("Usage: %s host\n", argv[0]);
  }

  install_signal_handler(SIGINT, catch_int, SA_RESTART);

  sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0)
    syserr("socket");

  drop_to_nobody();

  struct ping_info ping_info;
  memset(&ping_info, 0, sizeof(ping_info));

  while (!finish) {
    send_ping_request(sock, argv[1]);

    while (!receive_ping_reply(sock, &ping_info)) {
    }

    print_info(ping_info);

    sleep(1);
  }

  if (close(sock) == -1)
    syserr("close");

  return 0;
}
