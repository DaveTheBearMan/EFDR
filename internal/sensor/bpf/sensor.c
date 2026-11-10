//go:build ignore

// The XDR sensor: exec, outbound connect and sendmsg, and raw-socket
// events, written to one ring buffer. It observes only: no program here
// denies anything. Built with `make bpf`; the object is checked in.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10
#define AF_PACKET 17
#define SOCK_RAW 3

enum { EXEC = 1, CONNECT, SEND, SOCKET };

/* Kernel types, cut down to the fields read here; their offsets are
 * fixed up against the running kernel's BTF at load time. */
struct task_struct {
	struct task_struct *real_parent;
	int tgid;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_process_exec {
	__u32 __data_loc_filename;
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_enter {
	unsigned long args[6];
} __attribute__((preserve_access_index));

struct event {
	__u32 kind;
	__u32 pid, ppid, uid;
	__u16 family, type; /* connect/send: type holds the IP protocol */
	__u16 port;         /* host order */
	__u16 pad;
	__u8 addr[16];      /* IPv4 in the first 4 bytes */
	char comm[16];
	char filename[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline struct event *reserve(__u32 kind)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->kind = kind;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

SEC("tracepoint/sched/sched_process_exec")
int exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	struct event *e = reserve(EXEC);
	if (!e)
		return 0;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
				  (void *)ctx + (ctx->__data_loc_filename & 0xffff));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int sock(struct trace_event_raw_sys_enter *ctx)
{
	__u64 family = ctx->args[0], type = ctx->args[1];
	if (family != AF_PACKET &&
	    !((family == AF_INET || family == AF_INET6) && (type & 0xf) == SOCK_RAW))
		return 0;
	struct event *e = reserve(SOCKET);
	if (!e)
		return 0;
	e->family = family;
	e->type = type;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int loopback4(__u32 ip)
{
	return (ip & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000);
}

static __always_inline int out4(struct bpf_sock_addr *ctx, __u32 kind)
{
	__u32 ip = ctx->user_ip4;
	if (loopback4(ip))
		return 1;
	struct event *e = reserve(kind);
	if (!e)
		return 1;
	e->family = AF_INET;
	e->type = ctx->protocol;
	e->port = bpf_ntohs(ctx->user_port);
	__builtin_memcpy(e->addr, &ip, sizeof(ip));
	bpf_ringbuf_submit(e, 0);
	return 1;
}

static __always_inline int out6(struct bpf_sock_addr *ctx, __u32 kind)
{
	__u32 ip[4];
	ip[0] = ctx->user_ip6[0];
	ip[1] = ctx->user_ip6[1];
	ip[2] = ctx->user_ip6[2];
	ip[3] = ctx->user_ip6[3];
	if (!ip[0] && !ip[1]) {
		if (!ip[2] && ip[3] == bpf_htonl(1))
			return 1; /* ::1 */
		if (ip[2] == bpf_htonl(0xffff) && loopback4(ip[3]))
			return 1; /* ::ffff:127.0.0.0/104 */
	}
	struct event *e = reserve(kind);
	if (!e)
		return 1;
	e->family = AF_INET6;
	e->type = ctx->protocol;
	e->port = bpf_ntohs(ctx->user_port);
	__builtin_memcpy(e->addr, ip, sizeof(ip));
	bpf_ringbuf_submit(e, 0);
	return 1;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) { return out4(ctx, CONNECT); }

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx) { return out6(ctx, CONNECT); }

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx) { return out4(ctx, SEND); }

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx) { return out6(ctx, SEND); }
