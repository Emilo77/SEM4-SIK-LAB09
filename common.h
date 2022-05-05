#ifndef _ERR_
#define _ERR_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "err.h"
#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

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
void fatal(const char *fmt, ...)
{
  va_list fmt_args;

  fprintf(stderr, "ERROR: ");
  va_start(fmt_args, fmt);
  vfprintf(stderr, fmt, fmt_args);
  va_end(fmt_args);
  fprintf(stderr, "\n");
  exit(EXIT_FAILURE);
}

unsigned short
in_cksum(unsigned short *addr, int len)
{
  int				nleft = len;
  int				sum = 0;
  unsigned short	*w = addr;
  unsigned short	answer = 0;

  /*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* 4mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(unsigned char *)w ;
    sum += answer;
  }

  /* 4add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);			/* add carry */
  answer = ~sum;				/* truncate to 16 bits */
  return(answer);
}

void drop_to_nobody() {

  struct passwd * nobody_passwd;

  nobody_passwd = getpwnam("nobody");
  if (nobody_passwd  == NULL)
    syserr("getpwnam");

  if (setgid(nobody_passwd -> pw_gid) != 0)
    syserr("setgid");
  if (setuid(nobody_passwd -> pw_uid) != 0)
    syserr("setuid");

  if (setuid(0) != -1)
    fatal("ERROR: Managed to regain root privileges?");

}

#endif
