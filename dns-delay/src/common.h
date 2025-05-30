#define TASK_COMM_LEN 16
#define MAX_DNS_NAME_LENGTH 256

#define TC_ACT_OK 0

struct dns_filter {
  char process_name[TASK_COMM_LEN];
  pid_t pid;
  char query[MAX_DNS_NAME_LENGTH];
  uint32_t server_ip;
};
