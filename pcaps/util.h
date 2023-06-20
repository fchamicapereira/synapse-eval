#pragma once

#include <arpa/inet.h>
#include <assert.h>
#include <byteswap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <iomanip>
#include <sstream>
#include <string>

#define MIN_THROUGHPUT_GIGABIT_PER_SEC 1   // Gbps
#define MAX_THROUGHPUT_GIGABIT_PER_SEC 100 // Gbps

#define MIN_PACKET_SIZE_BYTES 8
#define MAX_PACKET_SIZE_BYTES 1500

#define TRILLION 1000000000000LLU
#define BILLION 1000000000LLU

#define THOUSAND 1000LLU
#define MILLION 1000000LLU
#define BILLION 1000000000LLU

#define bit_to_byte(B) ((B) / 8)
#define byte_to_bit(B) ((B)*8)

#define gbps_to_bps(R) ((R)*BILLION)

typedef uint64_t time_ns_t;
typedef uint64_t time_ps_t;

#define min_to_s(T) ((T)*60)

#define s_to_min(T) ((T) / (double)(60))
#define s_to_us(T) ((T)*MILLION)
#define s_to_ns(T) ((T)*BILLION)

#define us_to_s(T) ((double)(T) / (double)(MILLION))
#define us_to_ns(T) ((T)*THOUSAND)

#define ns_to_s(T) ((double)(T) / (double)(BILLION))
#define ns_to_us(T) ((T) / THOUSAND)
#define ns_to_ps(T) ((time_ps_t)((T)*THOUSAND))

#define ps_to_ns(T) ((time_ns_t)((double)(T) / (double)THOUSAND))

inline std::string fmt(uint64_t n) {
  auto ss = std::stringstream();
  auto rem = n % 1000;
  n /= 1000;

  if (n > 0) {
    ss << fmt(n);
    ss << "," << std::setfill('0') << std::setw(3) << rem;
  } else {
    ss << rem;
  }

  return ss.str();
}

/* Compute checksum for count bytes starting at addr, using one's complement of
 * one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr,
                                       unsigned int count) {
  unsigned long sum = 0;
  while (count > 1) {
    sum += *addr++;
    count -= 2;
  }
  // if any bytes left, pad the bytes and add
  if (count > 0) {
    sum += ((*addr) & htons(0xFF00));
  }
  // Fold sum to 16 bits: add carrier to result
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  // one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

/* set ip checksum of a given ip header*/
inline void compute_ip_checksum(iphdr *iphdrp) {
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short *)iphdrp, iphdrp->ihl << 2);
}

/* set tcp checksum: given IP header and UDP datagram */
inline void compute_udp_checksum(iphdr *pIph, unsigned short *ipPayload) {
  unsigned long sum = 0;
  udphdr *udphdrp = (udphdr *)(ipPayload);
  unsigned short udpLen = htons(udphdrp->len);
  // printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~udp len=%dn", udpLen);
  // add the pseudo header
  // printf("add pseudo headern");
  // the source ip
  sum += (pIph->saddr >> 16) & 0xFFFF;
  sum += (pIph->saddr) & 0xFFFF;
  // the dest ip
  sum += (pIph->daddr >> 16) & 0xFFFF;
  sum += (pIph->daddr) & 0xFFFF;
  // protocol and reserved: 17
  sum += htons(IPPROTO_UDP);
  // the length
  sum += udphdrp->len;

  // add the IP payload
  // printf("add ip payloadn");
  // initialize checksum to 0
  udphdrp->check = 0;
  while (udpLen > 1) {
    sum += *ipPayload++;
    udpLen -= 2;
  }
  // if any bytes left, pad the bytes and add
  if (udpLen > 0) {
    // printf("+++++++++++++++padding: %dn", udpLen);
    sum += ((*ipPayload) & htons(0xFF00));
  }
  // Fold sum to 16 bits: add carrier to result
  // printf("add carriern");
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  // printf("one's complementn");
  sum = ~sum;
  // set computation result
  udphdrp->check =
      ((unsigned short)sum == 0x0000) ? 0xFFFF : (unsigned short)sum;
}

inline long get_file_size(const char *fname) {
  assert(fname);
  FILE *fp = fopen(fname, "r");

  // checking if the file exist or not
  if (fp == NULL) {
    fprintf(stderr, "File %s not found\n", fname);
    exit(1);
  }

  fseek(fp, 0L, SEEK_END);
  auto res = ftell(fp);
  fclose(fp);

  return res;
}