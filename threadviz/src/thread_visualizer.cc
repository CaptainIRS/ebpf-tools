// clang-format off
#include <argp.h>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <memory>
#include <signal.h>
#include <stdio.h>
#include <thread>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "thread_visualizer.skel.h"

#include <perfetto.h>
#include <vector>
// clang-format on

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

class BPFDataSource : public perfetto::DataSource<BPFDataSource> {};

PERFETTO_DEFINE_DATA_SOURCE_STATIC_MEMBERS(BPFDataSource);

std::unique_ptr<perfetto::TracingSession> global_tracing_session;

std::unique_ptr<perfetto::protos::pbzero::FtraceEventBundle> bundle;

void init_tracer() {
  perfetto::TracingInitArgs args;
  args.backends |= perfetto::kInProcessBackend;
  perfetto::Tracing::Initialize(args);

  perfetto::DataSourceDescriptor dsd;
  dsd.set_name("linux.ftrace");
  BPFDataSource::Register(dsd);
  perfetto::ConsoleInterceptor::Register();
}

void stop_timeout(unsigned int trace_duration_ms) {
  std::this_thread::sleep_for(std::chrono::milliseconds(trace_duration_ms));
  exiting = true;
}

void start_tracing(unsigned int trace_duration_ms) {
  perfetto::TraceConfig cfg;
  cfg.set_duration_ms(trace_duration_ms);
  cfg.set_enable_extra_guardrails(false);
  cfg.add_buffers()->set_size_kb(1024 * 1024);
  auto *ftrace_ds_cfg = cfg.add_data_sources()->mutable_config();
  ftrace_ds_cfg->set_name("linux.ftrace");

  auto *stats_ds_cfg = cfg.add_data_sources()->mutable_config();
  stats_ds_cfg->set_name("linux.process_stats");

  global_tracing_session = perfetto::Tracing::NewTrace();
  global_tracing_session->Setup(cfg);
  global_tracing_session->StartBlocking();
}

void stop_tracing(std::string trace_file) {
  // Flush to make sure the last written event ends up in the trace.
  BPFDataSource::Trace([](BPFDataSource::TraceContext ctx) { ctx.Flush(); });

  // Stop tracing and read the trace data.
  global_tracing_session->StopBlocking();
  std::vector<char> trace_data(global_tracing_session->ReadTraceBlocking());

  // Write the result into a file.
  // Note: To save memory with longer traces, you can tell Perfetto to write
  // directly into a file by passing a file descriptor into Setup() above.
  std::ofstream output;
  const char *filename = "bpf.pftrace";
  output.open(filename, std::ios::out | std::ios::binary);
  output.write(&trace_data[0], static_cast<std::streamsize>(trace_data.size()));
  output.close();
  PERFETTO_LOG("Trace written to %s", filename);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event *e = (const struct event *)data;

  BPFDataSource::Trace([e](BPFDataSource::TraceContext ctx) {
    auto packet = ctx.NewTracePacket();
    packet->set_timestamp(e->timestamp);
    auto bundle = packet->set_ftrace_events();
    bundle->set_cpu(e->cpu);

    auto event = bundle->add_event();
    event->set_timestamp(e->timestamp);

    event->set_pid(e->pid);
    if (e->type == EVENT_TYPE_EXIT) {
      auto exit_event = event->set_sched_process_exit();
      exit_event->set_pid(e->sched_process_exit.pid);
      exit_event->set_comm(e->sched_process_exit.comm);
      exit_event->set_prio(e->sched_process_exit.prio);
      exit_event->set_tgid(e->sched_process_exit.tgid);
    } else if (e->type == EVENT_TYPE_FREE) {
      auto free_event = event->set_sched_process_free();
      free_event->set_pid(e->sched_process_free.pid);
      free_event->set_comm(e->sched_process_free.comm);
      free_event->set_prio(e->sched_process_free.prio);
    } else if (e->type == EVENT_TYPE_SCHED_SWITCH) {
      auto sched_switch_event = event->set_sched_switch();
      sched_switch_event->set_prev_pid(e->sched_switch.prev_pid);
      sched_switch_event->set_next_pid(e->sched_switch.next_pid);
      sched_switch_event->set_prev_comm(e->sched_switch.prev_comm);
      sched_switch_event->set_next_comm(e->sched_switch.next_comm);
      sched_switch_event->set_prev_prio(e->sched_switch.prev_prio);
      sched_switch_event->set_next_prio(e->sched_switch.next_prio);
      sched_switch_event->set_prev_state(e->sched_switch.prev_state);
    } else if (e->type == EVENT_TYPE_SCHED_WAKING) {
      auto sched_waking_event = event->set_sched_waking();
      sched_waking_event->set_pid(e->sched_waking.pid);
      sched_waking_event->set_comm(e->sched_waking.comm);
      sched_waking_event->set_prio(e->sched_waking.prio);
      sched_waking_event->set_target_cpu(e->sched_waking.target_cpu);
    } else if (e->type == EVENT_TYPE_SCHED_WAKEUP) {
      auto sched_wakeup_event = event->set_sched_wakeup();
      sched_wakeup_event->set_pid(e->sched_wakeup.pid);
      sched_wakeup_event->set_comm(e->sched_wakeup.comm);
      sched_wakeup_event->set_prio(e->sched_wakeup.prio);
      sched_wakeup_event->set_target_cpu(e->sched_wakeup.target_cpu);
    } else if (e->type == EVENT_TYPE_SCHED_WAKEUP_NEW) {
      auto sched_wakeup_new_event = event->set_sched_wakeup_new();
      sched_wakeup_new_event->set_pid(e->sched_wakeup_new.pid);
      sched_wakeup_new_event->set_comm(e->sched_wakeup_new.comm);
      sched_wakeup_new_event->set_prio(e->sched_wakeup_new.prio);
      sched_wakeup_new_event->set_target_cpu(e->sched_wakeup_new.target_cpu);
    } else if (e->type == EVENT_TYPE_NEWTASK) {
      auto newtask_event = event->set_task_newtask();
      newtask_event->set_pid(e->sched_task_new.pid);
      newtask_event->set_comm(e->sched_task_new.comm);
      newtask_event->set_clone_flags(e->sched_task_new.clone_flags);
      newtask_event->set_oom_score_adj(e->sched_task_new.oom_score_adj);
    } else if (e->type == EVENT_TYPE_RENAME) {
      auto rename_event = event->set_task_rename();
      rename_event->set_pid(e->sched_task_rename.pid);
      rename_event->set_newcomm(e->sched_task_rename.newcomm);
      rename_event->set_oldcomm(e->sched_task_rename.oldcomm);
      rename_event->set_oom_score_adj(e->sched_task_rename.oom_score_adj);
    }
  });

  return 0;
}

void process_stats() {
  while (!exiting) {
    BPFDataSource::Trace([](BPFDataSource::TraceContext ctx) {
      auto packet = ctx.NewTracePacket();
      packet->set_timestamp(perfetto::base::GetBootTimeNs().count());
      auto tree = packet->set_process_tree();
      std::vector<uint32_t> pids;
      for (const auto &entry : std::filesystem::directory_iterator("/proc")) {
        if (entry.is_directory()) {
          std::string name = entry.path().filename().string();
          if (std::all_of(name.begin(), name.end(), ::isdigit)) {
            pids.push_back(std::stoi(name));
          }
        }
      }
      std::set<uint32_t> seen_pids;
      for (const auto &pid : pids) {
        std::ifstream status_file("/proc/" + std::to_string(pid) + "/status");
        std::ifstream stat_file("/proc/" + std::to_string(pid) + "/stat");
        std::vector<std::string> status_content;
        std::string stat_content;
        if (status_file.is_open()) {
          std::string line;
          while (std::getline(status_file, line)) {
            status_content.push_back(line);
          }
          status_file.close();
        }
        if (stat_file.is_open()) {
          std::string line;
          while (std::getline(stat_file, line)) {
            stat_content = line;
          }
          stat_file.close();
        }
        int32_t tgid = 0, tid = 0, ppid = 0, uid = 0;
        uint64_t utime, stime, starttime;
        std::string comm;
        if (sscanf(stat_content.c_str(),
                   "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u "
                   "%*u %*u %*u %" SCNu64 " %" SCNu64 " %*d %*d %*d %*d %*d "
                   "%*d %" SCNu64 "",
                   &utime, &stime, &starttime) != 3) {
          continue;
        }
        for (auto &line : status_content) {
          if (line.find("Tgid:") != std::string::npos) {
            tgid = std::stoi(line.substr(line.find(":") + 1));
          }
          if (line.find("Pid:") != std::string::npos) {
            tid = std::stoi(line.substr(line.find(":") + 1));
          }
          if (line.find("PPid:") != std::string::npos) {
            ppid = std::stoi(line.substr(line.find(":") + 1));
          }
          if (line.find("Uid:") != std::string::npos) {
            uid = std::stoi(line.substr(line.find(":") + 1));
          }
          if (line.find("Name:") != std::string::npos) {
            comm = line.substr(line.find(":") + 1);
            comm.erase(0, comm.find_first_not_of(" \t"));
            comm.erase(comm.find_last_not_of(" \t") + 1);
          }
        }
        if (tgid < 0 || tid < 0) {
          continue;
        }
        if (seen_pids.find(tgid) == seen_pids.end()) {
          auto proc = tree->add_processes();
          proc->set_pid(tgid);
          proc->set_ppid(ppid);
          proc->set_uid(uid);
          std::string cmdline_file =
              "/proc/" + std::to_string(tgid) + "/cmdline";
          std::string cmdline = "";
          std::ifstream cmdline_file_stream(cmdline_file);
          bool is_cmdline_empty = true;
          if (cmdline_file_stream.is_open()) {
            while (std::getline(cmdline_file_stream, cmdline, '\0')) {
              if (!cmdline.empty() || cmdline_file_stream.gcount() > 0) {
                proc->add_cmdline(cmdline);
                is_cmdline_empty = false;
              }
            }
          }
          if (is_cmdline_empty) {
            proc->add_cmdline(comm);
          }
          proc->set_process_start_from_boot(starttime);

          seen_pids.insert(tgid);
        }
        if (pid != tgid) {
          auto thread = tree->add_threads();
          thread->set_tid(pid);
          thread->set_tgid(tgid);
          thread->set_name(comm);
          seen_pids.insert(pid);
        }
      }
    });
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

int main(int argc, char **argv) {
  int c;
  unsigned int trace_duration_ms = 10000;
  bool debug_logs_enabled = false;
  const char *trace_file = "bpf.pftrace";
  while ((c = getopt(argc, argv, "f:t:d")) != -1) {
    switch (c) {
    case 'd':
      debug_logs_enabled = true;
      break;
    case 't':
      trace_duration_ms = atoi(optarg);
      break;
    case 'f':
      trace_file = optarg;
      break;
    default:
      fprintf(stderr,
              "Usage: %s [-t trace_duration_ms (1000)] [-f trace_file "
              "(bpf.pftrace)] [-d]\n",
              argv[0]);
      return 1;
    }
  }
  init_tracer();
  start_tracing(trace_duration_ms);
  struct ring_buffer *rb = NULL;
  struct thread_visualizer_bpf *skel;
  int err;

  std::thread process_stats_thread(process_stats),
      stop_timeout_thread(stop_timeout, trace_duration_ms);
  stop_timeout_thread.detach();

  if (debug_logs_enabled) {
    libbpf_set_print(libbpf_print_fn);
  }

  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Load and verify BPF application */
  skel = thread_visualizer_bpf::open();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = thread_visualizer_bpf::load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = thread_visualizer_bpf::attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }
  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  process_stats_thread.join();
  stop_tracing(trace_file);

  ring_buffer__free(rb);
  thread_visualizer_bpf::destroy(skel);

  return err < 0 ? -err : 0;
}
