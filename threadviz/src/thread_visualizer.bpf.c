// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
// clang-format on

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile long wakeup_data_size = 1000 * sizeof(struct event);

static __always_inline long get_flags() {
  long sz;

  if (!wakeup_data_size)
    return 0;

  sz = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
  return sz >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
  struct task_struct *task;
  struct event *e;
  pid_t pid;
  u64 ts;

  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  task = (struct task_struct *)bpf_get_current_task();

  e->type = EVENT_TYPE_EXIT;
  e->timestamp = ts;
  e->cpu = bpf_get_smp_processor_id();
  e->pid = pid;
  e->sched_process_exit.pid = ctx->pid;
  e->sched_process_exit.tgid = BPF_CORE_READ(task, tgid);
  e->sched_process_exit.prio = ctx->prio;
  bpf_probe_read_str(&e->sched_process_exit.comm,
                     sizeof(e->sched_process_exit.comm), (void *)ctx->comm);

  bpf_ringbuf_submit(e, get_flags());
  return 0;
}

SEC("tp/sched/sched_process_free")
int handle_wait(struct trace_event_raw_sched_process_wait *ctx) {
  struct task_struct *task;
  struct event *e;
  pid_t pid;
  u64 ts;

  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  task = (struct task_struct *)bpf_get_current_task();

  e->type = EVENT_TYPE_FREE;
  e->timestamp = ts;
  e->cpu = bpf_get_smp_processor_id();
  e->pid = pid;
  e->sched_process_free.pid = ctx->pid;
  e->sched_process_free.prio = ctx->prio;
  bpf_probe_read_str(&e->sched_process_free.comm,
                     sizeof(e->sched_process_free.comm), (void *)ctx->comm);

  bpf_ringbuf_submit(e, get_flags());
  return 0;
}

SEC("tp/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx) {
  struct task_struct *task;
  struct event *e;
  pid_t pid;
  u64 ts;

  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  task = (struct task_struct *)bpf_get_current_task();

  e->type = EVENT_TYPE_SCHED_SWITCH;
  e->timestamp = ts;
  e->cpu = bpf_get_smp_processor_id();
  e->pid = pid;
  e->sched_switch.prev_pid = ctx->prev_pid;
  e->sched_switch.prev_prio = ctx->prev_prio;
  e->sched_switch.prev_state = ctx->prev_state;
  e->sched_switch.next_pid = ctx->next_pid;
  e->sched_switch.next_prio = ctx->next_prio;
  bpf_probe_read_str(&e->sched_switch.prev_comm,
                     sizeof(e->sched_switch.prev_comm), (void *)ctx->prev_comm);
  bpf_probe_read_str(&e->sched_switch.next_comm,
                     sizeof(e->sched_switch.next_comm), (void *)ctx->next_comm);

  bpf_ringbuf_submit(e, get_flags());
  return 0;
}

SEC("tp/sched/sched_wakeup")
int handle_wakeup(struct trace_event_raw_sched_wakeup_template *ctx) {
  struct task_struct *task;
  struct event *e;
  pid_t pid;
  u64 ts;

  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  task = (struct task_struct *)bpf_get_current_task();

  e->type = EVENT_TYPE_SCHED_WAKEUP;
  e->timestamp = ts;
  e->cpu = bpf_get_smp_processor_id();
  e->pid = pid;
  e->sched_wakeup.pid = ctx->pid;
  e->sched_wakeup.prio = ctx->prio;
  e->sched_wakeup.target_cpu = ctx->target_cpu;
  bpf_probe_read_str(&e->sched_wakeup.comm, sizeof(e->sched_wakeup.comm),
                     (void *)ctx->comm);

  bpf_ringbuf_submit(e, get_flags());
  return 0;
}

SEC("tp/sched/sched_waking")
int handle_waking(struct trace_event_raw_sched_wakeup_template *ctx) {
  struct task_struct *task;
  struct event *e;
  pid_t pid;
  u64 ts;

  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  task = (struct task_struct *)bpf_get_current_task();

  e->type = EVENT_TYPE_SCHED_WAKING;
  e->timestamp = ts;
  e->cpu = bpf_get_smp_processor_id();
  e->pid = pid;
  e->sched_waking.pid = ctx->pid;
  e->sched_waking.prio = ctx->prio;
  e->sched_waking.target_cpu = ctx->target_cpu;
  bpf_probe_read_str(&e->sched_waking.comm, sizeof(e->sched_waking.comm),
                     (void *)ctx->comm);

  bpf_ringbuf_submit(e, get_flags());
  return 0;
}

SEC("tp/sched/sched_wakeup_new")
int handle_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx) {
  struct task_struct *task;
  struct event *e;
  pid_t pid;
  u64 ts;

  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  task = (struct task_struct *)bpf_get_current_task();

  e->type = EVENT_TYPE_SCHED_WAKEUP_NEW;
  e->timestamp = ts;
  e->cpu = bpf_get_smp_processor_id();
  e->pid = pid;
  e->sched_wakeup_new.pid = ctx->pid;
  e->sched_wakeup_new.prio = ctx->prio;
  e->sched_wakeup_new.target_cpu = ctx->target_cpu;
  bpf_probe_read_str(&e->sched_wakeup_new.comm,
                     sizeof(e->sched_wakeup_new.comm), (void *)ctx->comm);

  bpf_ringbuf_submit(e, get_flags());
  return 0;
}

SEC("tp/task/task_newtask")
int handle_newtask(struct trace_event_raw_task_newtask *ctx) {
  struct task_struct *task;
  struct event *e;
  pid_t pid;
  u64 ts;

  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  task = (struct task_struct *)bpf_get_current_task();

  e->type = EVENT_TYPE_NEWTASK;
  e->timestamp = ts;
  e->cpu = bpf_get_smp_processor_id();
  e->pid = pid;
  e->sched_task_new.pid = ctx->pid;
  e->sched_task_new.clone_flags = ctx->clone_flags;
  e->sched_task_new.oom_score_adj = ctx->oom_score_adj;
  bpf_probe_read_str(&e->sched_task_new.comm, sizeof(e->sched_task_new.comm),
                     (void *)ctx->comm);

  bpf_ringbuf_submit(e, get_flags());
  return 0;
}

SEC("tp/task/task_rename")
int handle_rename(struct trace_event_raw_task_rename *ctx) {
  struct task_struct *task;
  struct event *e;
  pid_t pid;
  u64 ts;

  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  task = (struct task_struct *)bpf_get_current_task();

  e->type = EVENT_TYPE_RENAME;
  e->timestamp = ts;
  e->cpu = bpf_get_smp_processor_id();
  e->pid = pid;
  e->sched_task_rename.pid = ctx->pid;
  e->sched_task_rename.oom_score_adj = ctx->oom_score_adj;
  bpf_probe_read_str(&e->sched_task_rename.newcomm,
                     sizeof(e->sched_task_rename.newcomm),
                     (void *)ctx->newcomm);
  bpf_probe_read_str(&e->sched_task_rename.oldcomm,
                     sizeof(e->sched_task_rename.oldcomm),
                     (void *)ctx->oldcomm);

  bpf_ringbuf_submit(e, get_flags());
  return 0;
}

char _license[] SEC("license") = "GPL";
