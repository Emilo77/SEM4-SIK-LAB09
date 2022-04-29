#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// this sets ICMP declaration
#include <netinet/ip_icmp.h>
#include "err.h"

#define BSIZE 1000
#define ICMP_HEADER_LEN 8
#define MAX_ID 1 << 16


unsigned short in_cksum(unsigned short *addr, int len);
void drop_to_nobody();

void send_ping_request(int sock, char* s_send_addr) {
  struct addrinfo addr_hints;
  struct addrinfo *addr_result;
  struct sockaddr_in send_addr;
  
  struct icmp* icmp;
  
  char send_buffer[BSIZE];
  
  int err = 0;
  ssize_t data_len = 0;
  ssize_t icmp_len = 0;
  ssize_t len = 0;
  
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
      ((struct sockaddr_in*) (addr_result->ai_addr))->sin_addr.s_addr;
  send_addr.sin_port = htons(0);
  freeaddrinfo(addr_result);

  memset(send_buffer, 0, sizeof(send_buffer));
  // initializing ICMP header
  icmp = (struct icmp *) send_buffer;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_id = htons(getpid() % MAX_ID); // process identified by PID
  // modulo MAX_ID in case pid is greater than 2^16
  icmp->icmp_seq = htons(0); // sequential number
  data_len = snprintf(((char*) send_buffer+ICMP_HEADER_LEN),
                      sizeof(send_buffer)-ICMP_HEADER_LEN, "BASIC PING!");
  if (data_len < 1)
    syserr("snprintf");
  icmp_len = data_len + ICMP_HEADER_LEN; // packet is filled with 0
  icmp->icmp_cksum = 0; // checksum computed over whole ICMP package
  icmp->icmp_cksum = in_cksum((unsigned short*) icmp, icmp_len);

  len = sendto(sock, (void*) icmp, icmp_len, 0, (struct sockaddr *) &send_addr, 
               (socklen_t) sizeof(send_addr));
  if (icmp_len != (ssize_t) len)
    syserr("partial / failed write");

  printf("wrote %zd bytes\n", len);
}

int receive_ping_reply(int sock) {
  struct sockaddr_in rcv_addr;
  socklen_t rcv_addr_len;
  
  struct ip* ip;
  struct icmp* icmp;
  
  char rcv_buffer[BSIZE];
  
  ssize_t ip_header_len = 0;
  ssize_t data_len = 0;
  ssize_t icmp_len = 0;
  ssize_t len;
  
  memset(rcv_buffer, 0, sizeof(rcv_buffer));
  rcv_addr_len = (socklen_t) sizeof(rcv_addr);
  len = recvfrom(sock, (void*) rcv_buffer, sizeof(rcv_buffer), 0, 
                 (struct sockaddr *) &rcv_addr, &rcv_addr_len);
  
  if (len == -1)
    syserr("failed read");
  
  printf("received %zd bytes from %s\n", len, inet_ntoa(rcv_addr.sin_addr));
  
  // recvfrom returns whole packet (with IP header)
  ip = (struct ip*) rcv_buffer;
  ip_header_len = ip->ip_hl << 2; // IP header len is in 4-byte words
  
  icmp = (struct icmp*) (rcv_buffer + ip_header_len); // ICMP header follows IP
  icmp_len = len - ip_header_len;

  if (icmp_len < ICMP_HEADER_LEN)
    fatal("icmp header len (%d) < ICMP_HEADER_LEN", icmp_len);
  
  if (icmp->icmp_type != ICMP_ECHOREPLY) {
    printf("strange reply type (%d)\n", icmp->icmp_type);
    return 0;
  }

  if (ntohs(icmp->icmp_id) != getpid() % MAX_ID)
    fatal("reply with id %d different from my pid %d", ntohs(icmp->icmp_id), getpid());

  data_len = len - ip_header_len - ICMP_HEADER_LEN;
  printf("correct ICMP echo reply; payload size: %zd content: %.*s\n", data_len,
         (int) data_len, (rcv_buffer+ip_header_len+ICMP_HEADER_LEN));
  return 1;
}

int main(int argc, char *argv[]) {
  int sock;
  
  if (argc < 2) {
    fatal("Usage: %s host\n", argv[0]);
  }

  sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0)
    syserr("socket");

  drop_to_nobody();

  send_ping_request(sock, argv[1]);

  while (!receive_ping_reply(sock))
    ;

  if (close(sock) == -1) 
    syserr("close"); 

  return 0;
}


