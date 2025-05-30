#include "syscall_blocker.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "common.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo) { stop = 1; }

static int should_include(char **syscalls, int num_syscalls,
                          char *syscall_name) {
  for (int i = 0; i < num_syscalls; i++) {
    if (strcmp(syscalls[i], syscall_name) == 0)
      return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  int c, num_syscalls;
  char **syscalls = 0;
  char *endptr;
  uint32_t uid, ns_inum;
  bool uid_set = false, ns_inum_set = false, debug_logs_enabled = false;
  while ((c = getopt(argc, argv, "s:u:n:d")) != -1) {
    switch (c) {
    case 's':
      num_syscalls = 0;
      for (char *p = strtok(optarg, ","); p; p = strtok(NULL, ",")) {
        num_syscalls++;
        syscalls = (char **)realloc(syscalls, num_syscalls * sizeof(char *));
        syscalls[num_syscalls - 1] = p;
      }
      break;
    case 'u':
      uid = atoi(optarg);
      uid_set = true;
      break;
    case 'n':
      ns_inum = atoi(optarg);
      ns_inum_set = true;
      break;
    case 'd':
      debug_logs_enabled = true;
      break;
    default:
      fprintf(stderr,
              "Usage: %s -u <uid> -n <ns_inum> [-s syscall1,syscall2,...]\n",
              argv[0]);
      return 1;
    }
  }
  if (!uid_set || !ns_inum_set) {
    fprintf(stderr,
            "Usage: %s -u <uid> -n <ns_inum> [-s syscall1,syscall2,...]\n",
            argv[0]);
    return 1;
  }
  fprintf(stderr, "Blocking %d syscalls: ", num_syscalls);
  for (int i = 0; i < num_syscalls; i++) {
    fprintf(stderr, "%s ", syscalls[i]);
  }
  fprintf(stderr, "\n");

  int err;

  /* Set up libbpf errors and debug info callback */
  if (debug_logs_enabled) {
    libbpf_set_print(libbpf_print_fn);
  }

  struct syscall_blocker_bpf *skel;
  skel = syscall_blocker_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  // A lot of what follows is just boilerplate directly from the skel.h file
  // generated by libbpf. The only thing that's different is how the BPF
  // programs are included. The gen:start and gen:end comments are used to
  // indicate where the generated code should be inserted.
  struct syscall_blocker_bpf *obj;

  obj = (struct syscall_blocker_bpf *)calloc(1, sizeof(*obj));
  if (!obj) {
    err = -ENOMEM;
    goto cleanup;
  }

  struct bpf_object_skeleton *s;
  struct bpf_map_skeleton *map __attribute__((unused));

  s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
  if (!s) {
    err = -ENOMEM;
    goto cleanup;
  }

  s->sz = sizeof(*s);
  s->name = "syscall_blocker_bpf";
  s->obj = &obj->obj;

  /* maps */
  s->map_cnt = 3;
  s->map_skel_sz = 24;
  s->maps = (struct bpf_map_skeleton *)calloc(
      s->map_cnt, sizeof(*s->maps) > 24 ? sizeof(*s->maps) : 24);
  if (!s->maps) {
    err = -ENOMEM;
    goto cleanup;
  }

  map = (struct bpf_map_skeleton *)((char *)s->maps + 0 * s->map_skel_sz);
  map->name = "syscall_filter_map";
  map->map = &obj->maps.syscall_filter_map;

  map = (struct bpf_map_skeleton *)((char *)s->maps + 1 * s->map_skel_sz);
  map->name = "syscall_.rodata";
  map->map = &obj->maps.rodata;

  map = (struct bpf_map_skeleton *)((char *)s->maps + 2 * s->map_skel_sz);
  map->name = "syscall.kconfig";
  map->map = &obj->maps.kconfig;
  map->mmaped = (void **)&obj->kconfig;

  /* programs */
  s->prog_cnt = num_syscalls;
  s->prog_skel_sz = sizeof(*s->progs);
  s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
  if (!s->progs) {
    err = -ENOMEM;
    goto cleanup;
  }

  int cur_syscall = 0;
  fprintf(stderr, "Going to include syscalls\n");
  // HACK: select syscall is used as a stub to be replaced with the
  // actual syscall name by generate.py (for IDEs to not complain)
  // gen:start
  if (should_include(syscalls, num_syscalls, "syscall_name")) {
    fprintf(stderr, "Including syscall_name at %d\n", cur_syscall);
    s->progs[cur_syscall].name = "entry_probe_select";
    s->progs[cur_syscall].prog = &obj->progs.entry_probe_select;
    s->progs[cur_syscall].link = &obj->links.entry_probe_select;
    cur_syscall++;
  }
  // gen:end

  s->data = syscall_blocker_bpf__elf_bytes(&s->data_sz);

  obj->skeleton = s;

  err = bpf_object__open_skeleton(obj->skeleton, NULL);
  if (err)
    goto cleanup;

  err = syscall_blocker_bpf__load(obj);
  if (err) {
    syscall_blocker_bpf__destroy(obj);
    goto cleanup;
  }

  skel = obj;

  /* Attach tracepoint handler */
  err = syscall_blocker_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  struct syscall_filter filter;
  filter.uid = uid;
  filter.ns_inum = ns_inum;
  uint32_t index = 0;
  err = bpf_map__update_elem(skel->maps.syscall_filter_map, &index,
                             sizeof(index), &filter, sizeof(filter), BPF_ANY);
  if (err) {
    fprintf(stderr, "Failed to update syscall_filter_map\n");
    goto cleanup;
  }

  if (signal(SIGINT, sig_int) == SIG_ERR) {
    fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
    goto cleanup;
  }

  while (!stop) {
    sleep(1);
  }

cleanup:
  syscall_blocker_bpf__destroy(skel);
  return -err;
}
