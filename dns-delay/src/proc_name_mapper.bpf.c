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

/**
 * This BPF program is hooked to the tracepoint sys_enter_sendmsg.
 * This is because we need to know the PID of the process that is sending the DNS
 * query. The only available information from the user is the process name (not
 * PID). However from the classifier's context, we can only get the PID and not the
 * process name. So, this BPF program is used to map the process name to the
 * corresponding PID whenever a sendmsg syscall is made by the matching process.
 */

SEC("tp/syscalls/sys_enter_sendmsg")
int handle_tp(void *ctx) {
  char comm[TASK_COMM_LEN];
  // bpf_get_current_comm is not available in the context of a classifier
  // (BPF_PROG_TYPE_SCHED_CLS) and hence this workaround.
  if (bpf_get_current_comm(comm, TASK_COMM_LEN)) {
    bpf_printk("Failed to get comm\n");
    return 0;
  }
  u32 index = 0;
  struct dns_filter *filter = bpf_map_lookup_elem(&dns_filter_map, &index);
  if (!filter)
    return 0;
  // Compare strings old-school way (no libc in BPF)
  for (u32 i = 0; i < TASK_COMM_LEN; i++) {
    if (comm[i] == 0)
      break;
    if (comm[i] != filter->process_name[i])
      return 0;
  }

  index = 0;
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  filter->pid = pid;
  bpf_map_update_elem(&dns_filter_map, &index, filter, BPF_ANY);

  bpf_printk("sendmsg from %s", comm);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
