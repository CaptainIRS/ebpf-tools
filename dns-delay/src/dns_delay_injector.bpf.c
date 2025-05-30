#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct dns_filter);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_filter_map SEC(".maps");

struct dnshdr {
  uint16_t transaction_id;
  uint8_t rd : 1;      // Recursion desired
  uint8_t tc : 1;      // Truncated
  uint8_t aa : 1;      // Authoritive answer
  uint8_t opcode : 4;  // Opcode
  uint8_t qr : 1;      // Query/response flag
  uint8_t rcode : 4;   // Response code
  uint8_t cd : 1;      // Checking disabled
  uint8_t ad : 1;      // Authenticated data
  uint8_t z : 1;       // Z reserved bit
  uint8_t ra : 1;      // Recursion available
  uint16_t q_count;    // Number of questions
  uint16_t ans_count;  // Number of answer RRs
  uint16_t auth_count; // Number of authority RRs
  uint16_t add_count;  // Number of resource RRs
};

SEC("classifier")
int tc_classifier(struct __sk_buff *ctx) {
  // bpf_get_current_pid_tgid is available in BPF_PROG_TYPE_SCHED_CLS only
  // from kernal 6.10 and hence the requirement mentioned in README.
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  u32 index = 0;
  struct dns_filter *filter = bpf_map_lookup_elem(&dns_filter_map, &index);
  if (!filter || filter->pid != pid)
    return TC_ACT_OK;

  void *data_end = (void *)(__u64)ctx->data_end;
  void *data = (void *)(__u64)ctx->data;

  struct ethhdr *l2;
  struct iphdr *l3;
  struct udphdr *l4;
  struct dnshdr *dnshdr;

  l2 = data;
  if ((void *)(l2 + 1) > data_end)
    return TC_ACT_OK;

  l3 = (struct iphdr *)(l2 + 1);
  if ((void *)(l3 + 1) > data_end)
    return TC_ACT_OK;

  if (l3->protocol != IPPROTO_UDP)
    return TC_ACT_OK;

  if (!filter->server_ip) {
  } // No target IP, continue
  else if (l3->daddr != filter->server_ip)
    return TC_ACT_OK;

  l4 = (struct udphdr *)(l3 + 1);
  if ((void *)(l4 + 1) > data_end)
    return TC_ACT_OK;

  if (bpf_ntohs(l4->dest) != 53)
    return TC_ACT_OK;

  dnshdr = (struct dnshdr *)(l4 + 1);
  if ((void *)(dnshdr + 1) > data_end)
    return TC_ACT_OK;

  // Only process DNS queries
  if (dnshdr->qr != 0 || dnshdr->opcode != 0)
    return TC_ACT_OK;

  char query[MAX_DNS_NAME_LENGTH];
  size_t query_index = 0;

  // Extract the query from the DNS packet
  // Encoded with sort of a length-prefixed string like 3www6google3com0
  char *ptr = (char *)(dnshdr + 1);
  for (int i = 0; i < MAX_DNS_NAME_LENGTH - 1; i++) {
    if ((void *)(ptr + i) >= data_end)
      return TC_ACT_OK;
    uint8_t len = ptr[i];
    if (len == 0)
      break;
    if (i != 0) {
      query[query_index++] = '.';
    }
    for (int j = i + 1; j < i + 1 + len; j++) {
      if ((void *)(ptr + j) >= data_end || query_index >= MAX_DNS_NAME_LENGTH)
        return TC_ACT_OK;
      query[query_index++] = ptr[j];
    }
    i += len;
  }
  query[query_index] = 0;

  if (!filter->query[0]) {
  } // No target query, continue
  else {
    // Compare strings old-school way (no libc in BPF)
    for (int i = 0; i < MAX_DNS_NAME_LENGTH; i++) {
      if (filter->query[i] == 0)
        break;
      if (query[i] != filter->query[i])
        return TC_ACT_OK;
    }
  }
  bpf_printk("DNS query from PID %d: %s/%s to %d.%d.%d.%d", pid, query,
             filter->query, l3->daddr & 0xFF, (l3->daddr >> 8) & 0xFF,
             (l3->daddr >> 16) & 0xFF, (l3->daddr >> 24) & 0xFF);
  // Set mark to 1 for further processing by subsequent qdiscs
  ctx->mark = 1;

  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
