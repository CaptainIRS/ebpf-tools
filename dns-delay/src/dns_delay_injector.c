#include "dns_delay_injector.skel.h"
#include "proc_name_mapper.skel.h"
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>

#include "common.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

struct target_process_name_container {
  char name[16];
};

int main(int argc, char **argv) {
  int c;
  uint32_t index = 0;
  char *target_process_name = 0, *target_ip_str = 0, *target_query_str = 0;

  while ((c = getopt(argc, argv, "p:t:q:")) != -1) {
    switch (c) {
    case 'p':
      fprintf(stderr, "target_process_name: %s\n", optarg);
      target_process_name = optarg;
      break;
    case 't':
      fprintf(stderr, "target_ip: %s\n", optarg);
      target_ip_str = optarg;
      break;
    case 'q':
      fprintf(stderr, "target_query: %s\n", optarg);
      target_query_str = optarg;
      break;
    default:
      fprintf(
          stderr,
          "Usage: %s -p target_process_name [-t target_ip] [-q target_query]\n",
          argv[0]);
      return 1;
    }
  }

  if (!target_process_name) {
    // Target process name is required as we don't wanna mess with the whole
    // system
    fprintf(
        stderr,
        "Usage: %s -p target_process_name [-t target_ip] [-q target_query]\n",
        argv[0]);
    return 1;
  }

  LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = if_nametoindex("lo"),
              .attach_point = BPF_TC_EGRESS);
  LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
  bool hook_created = false;

  struct dns_delay_injector_bpf *skel;
  struct proc_name_mapper_bpf *proc_skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  proc_skel = proc_name_mapper_bpf__open();
  if (!proc_skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    goto cleanup;
  }

  skel = dns_delay_injector_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    goto cleanup;
  }

  struct dns_filter filter;
  if (target_ip_str) {
    uint32_t target_ip = inet_addr(target_ip_str);
    if (target_ip == INADDR_NONE) {
      fprintf(stderr, "Invalid target IP\n");
      goto cleanup;
    }
    filter.server_ip = target_ip;
  }
  strncpy(filter.process_name, target_process_name,
          sizeof(filter.process_name));
  if (target_query_str) {
    strncpy(filter.query, target_query_str, sizeof(filter.query));
  }

  err = proc_name_mapper_bpf__load(proc_skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton\n");
    goto cleanup;
  }

  err = proc_name_mapper_bpf__attach(proc_skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  err = dns_delay_injector_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton\n");
    goto cleanup;
  }

  err = bpf_map__update_elem(skel->maps.dns_filter_map, &index, sizeof(index),
                             &filter, sizeof(filter), BPF_ANY);
  if (err) {
    fprintf(stderr, "Failed to update BPF map %d\n", err);
    goto cleanup;
  }

  err = bpf_tc_hook_create(&tc_hook);
  if (!err)
    hook_created = true;
  if (err && err != -EEXIST) {
    fprintf(stderr, "Failed to create TC hook: %d\n", err);
    goto cleanup;
  }

  tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_classifier);
  err = bpf_tc_attach(&tc_hook, &tc_opts);
  if (err) {
    fprintf(stderr, "Failed to attach TC: %d\n", err);
    goto cleanup;
  }

  if (signal(SIGINT, sig_int) == SIG_ERR) {
    err = errno;
    fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
    goto cleanup;
  }

  while (!exiting) {
    sleep(1);
  }

  tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
  err = bpf_tc_detach(&tc_hook, &tc_opts);
  if (err) {
    fprintf(stderr, "Failed to detach TC: %d\n", err);
    goto cleanup;
  }

cleanup:
  if (hook_created)
    bpf_tc_hook_destroy(&tc_hook);
  if (skel)
    dns_delay_injector_bpf__destroy(skel);
  if (proc_skel)
    proc_name_mapper_bpf__destroy(proc_skel);
  return -err;
}
