/*
 * AegisKernel eBPF Tracepoint Monitor (Ring-0)
 * Intercepts sys_enter_execve and sys_enter_openat for zero-trust runtime security.
 */

#ifndef __BPF_TRACING__
#define __BPF_TRACING__
#endif

// Maps and ring buffer definitions for kernel space -> user space event streaming
struct event_t {
    __u32 pid;
    __u32 uid;
    __u32 syscall_id;
    char comm[64];
    char filename[256];
};

// Simulated BPF Map structure
int _aegis_bpf_version = 1;
unsigned long long _ringbuf_max_entries = 4096;
