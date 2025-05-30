#define TASK_COMM_LEN 16

struct sched_switch_event {
  char prev_comm[TASK_COMM_LEN];
  uint32_t prev_pid;
  uint32_t prev_prio;
  uint64_t prev_state;
  char next_comm[TASK_COMM_LEN];
  uint32_t next_pid;
  uint32_t next_prio;
};

struct sched_wakeup_event {
  char comm[TASK_COMM_LEN];
  uint32_t pid;
  uint32_t prio;
  uint32_t target_cpu;
};

struct sched_waking_event {
  char comm[TASK_COMM_LEN];
  uint32_t pid;
  uint32_t prio;
  uint32_t target_cpu;
};

struct sched_wakeup_new_event {
  char comm[TASK_COMM_LEN];
  uint32_t pid;
  uint32_t prio;
  uint32_t target_cpu;
};

struct sched_process_exit_event {
  char comm[TASK_COMM_LEN];
  uint32_t pid;
  uint32_t tgid;
  uint32_t prio;
};

struct sched_process_free_event {
  char comm[TASK_COMM_LEN];
  uint32_t pid;
  uint32_t prio;
};

struct sched_task_new_event {
  char comm[TASK_COMM_LEN];
  uint32_t pid;
  uint64_t clone_flags;
  int32_t oom_score_adj;
};

struct sched_task_rename_event {
  uint32_t pid;
  char newcomm[TASK_COMM_LEN];
  char oldcomm[TASK_COMM_LEN];
  int32_t oom_score_adj;
};

enum event_type {
  EVENT_TYPE_EXIT,
  EVENT_TYPE_FREE,
  EVENT_TYPE_SCHED_SWITCH,
  EVENT_TYPE_SCHED_WAKEUP,
  EVENT_TYPE_SCHED_WAKING,
  EVENT_TYPE_SCHED_WAKEUP_NEW,
  EVENT_TYPE_NEWTASK,
  EVENT_TYPE_RENAME,
};

struct event {
  enum event_type type;
  uint64_t timestamp;
  uint32_t cpu;
  uint32_t pid;
  union {
    struct sched_switch_event sched_switch;
    struct sched_wakeup_event sched_wakeup;
    struct sched_waking_event sched_waking;
    struct sched_wakeup_new_event sched_wakeup_new;
    struct sched_process_exit_event sched_process_exit;
    struct sched_process_free_event sched_process_free;
    struct sched_task_new_event sched_task_new;
    struct sched_task_rename_event sched_task_rename;
  };
};
