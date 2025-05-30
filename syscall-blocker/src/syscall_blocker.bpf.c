#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

#include "common.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct syscall_filter);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} syscall_filter_map SEC(".maps");

// gen:start
SEC("ksyscall/syscall_name")
int BPF_KSYSCALL(entry_probe_syscall_name, pid_t pid, int sig) {
  u32 index = 0;
  struct syscall_filter *filter =
      bpf_map_lookup_elem(&syscall_filter_map, &index);
  if (!filter) {
    return 0;
  }

  u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
  u32 caller_uid = bpf_get_current_uid_gid() >> 32;
  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));

  struct task_struct *current_task =
      (struct task_struct *)bpf_get_current_task();
  struct ns_common namespace = BPF_CORE_READ(current_task, nsproxy, mnt_ns, ns);
  u64 caller_ns_inum = namespace.inum;

  if (filter->uid == caller_uid && filter->ns_inum == caller_ns_inum) {
    bpf_printk("Blocked pid %d (%s) of user %d in mount ns %lld is calling "
               "syscall_name syscall.",
               caller_pid, comm, caller_uid, caller_ns_inum);
    bpf_override_return(ctx, -1);
  }
  return 0;
}
// gen:end

char _license[] SEC("license") = "GPL";
