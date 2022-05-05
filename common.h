#ifndef _ERR_
#define _ERR_

#include "err.h"
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define PRINT_ERRNO()                                                          \
  do {                                                                         \
    if (errno != 0) {                                                          \
      fprintf(stderr, "Error: errno %d in %s at %s:%d\n%s\n", errno, __func__, \
              __FILE__, __LINE__, strerror(errno));                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

// Set `errno` to 0 and evaluate `x`. If `errno` changed, describe it and exit.
#define CHECK_ERRNO(x)                                                         \
  do {                                                                         \
    errno = 0;                                                                 \
    (void)(x);                                                                 \
    PRINT_ERRNO();                                                             \
  } while (0)

/* Wypisuje informację o błędnym zakończeniu funkcji systemowej
i kończy działanie programu. */
void syserr(const char *fmt, ...) {
  va_list fmt_args;
  int errno1 = errno;

  fprintf(stderr, "ERROR: ");
  va_start(fmt_args, fmt);
  vfprintf(stderr, fmt, fmt_args);
  va_end(fmt_args);
  fprintf(stderr, " (%d; %s)\n", errno1, strerror(errno1));
  exit(EXIT_FAILURE);
}

/* Wypisuje informację o błędzie i kończy działanie programu. */
void fatal(const char *fmt, ...) {
  va_list fmt_args;

  fprintf(stderr, "ERROR: ");
  va_start(fmt_args, fmt);
  vfprintf(stderr, fmt, fmt_args);
  va_end(fmt_args);
  fprintf(stderr, "\n");
  exit(EXIT_FAILURE);
}

unsigned short in_cksum(unsigned short *addr, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  /* 4mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(unsigned char *)w;
    sum += answer;
  }

  /* 4add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = ~sum;                      /* truncate to 16 bits */
  return (answer);
}

void drop_to_nobody() {

  struct passwd *nobody_passwd;

  nobody_passwd = getpwnam("nobody");
  if (nobody_passwd == NULL)
    syserr("getpwnam");

  if (setgid(nobody_passwd->pw_gid) != 0)
    syserr("setgid");
  if (setuid(nobody_passwd->pw_uid) != 0)
    syserr("setuid");

  if (setuid(0) != -1)
    fatal("ERROR: Managed to regain root privileges?");
}

inline static void install_signal_handler(int signal, void (*handler)(int),
                                          int flags) {
  struct sigaction action;
  sigset_t block_mask;

  sigemptyset(&block_mask);
  action.sa_handler = handler;
  action.sa_mask = block_mask;
  action.sa_flags = flags;

  CHECK_ERRNO(sigaction(signal, &action, NULL));
}

#endif
