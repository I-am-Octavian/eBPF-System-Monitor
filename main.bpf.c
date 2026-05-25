#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf/bpf_core_read.h"
#include "main.h"

#define O_CREAT	   00000100

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

#define _PRINT2(_type, _pid)\
    do {\
        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);\
        if (!e) break;\
        e->type = (_type);\
        e->pid = (_pid);\
        e->filename[0] = '\0';\
        bpf_ringbuf_submit(e, 0);\
    } while (0)

#define _PRINT3(_type, _pid, _fname)\
    do {\
        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);\
        if (!e) break;\
        e->type = (_type);\
        e->pid = (_pid);\
        __builtin_memcpy(e->filename, (_fname), MAX_FILENAME_LEN);\
        bpf_ringbuf_submit(e, 0);\
    } while (0)

#define _MATCH_PRINT(_1, _2, _3, NAME, ...) NAME
#define PRINT(...) _MATCH_PRINT(__VA_ARGS__, _PRINT3, _PRINT2)(__VA_ARGS__)

// SEC("tracepoint/sched/sched_process_exec")
// int handle_process_exec(struct trace_event_raw_sched_process_exec* ctx)
// {
//     pid_t pid = ctx->pid;

//     PRINT(PROC_CREATE, pid);

//     return 0;
// }

SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork* ctx)
{
    pid_t pid = ctx->child_pid;

    PRINT(PROC_CREATE, pid);

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template* ctx)
{
    pid_t pid = ctx->pid;

    PRINT(PROC_EXIT, pid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat") // file open and file created
int handle_file_open(struct trace_event_raw_sys_enter* ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;;
    int flags = ctx->args[2];
    
    const char* filename = (const char*)ctx->args[1];
    char filename_u[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(filename_u, sizeof(filename_u), filename);

    if(flags & O_CREAT)
    {
        PRINT(FILE_CREATE, pid, filename_u);
    }
    else
    {
        PRINT(FILE_OPEN, pid, filename_u);
    }


    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close") // file close
int handle_sys_close(struct trace_event_raw_sys_enter* ctx)
{
    char filename_k[MAX_FILENAME_LEN];
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    int fd = ctx->args[0];// file descriptor

    if(fd < 0 || fd > 1023)
        return 0;
    
    struct task_struct* tsk = bpf_get_current_task_btf();
    
    struct files_struct *fdt = BPF_CORE_READ(tsk, files);
    struct file **files = BPF_CORE_READ(fdt, fdt, fd);
    if(files == NULL)
    {
        return 0;
    }

    struct file *file;
    bpf_probe_read_kernel(&file, sizeof(file), &files[fd]);

    if(file == NULL)
    {
        return 0;
    }

    const unsigned char* filename = BPF_CORE_READ(file, f_path.dentry, d_name.name);

    if (filename != NULL)
    {
        bpf_probe_read_kernel_str(filename_k, sizeof(filename_k), filename);
        PRINT(FILE_CLOSE, pid, filename_k);
    }

    return 0;
}
