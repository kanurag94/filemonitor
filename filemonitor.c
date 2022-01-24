#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char pname[DNAME_INLINE_LEN];
    char fname[DNAME_INLINE_LEN];
    char comm[TASK_COMM_LEN];
    char otype[TASK_COMM_LEN];
};


BPF_HASH(inodemap, u32, u32);
BPF_PERF_OUTPUT(events);

static int common(struct pt_regs *ctx, struct dentry *de, char *OPRN) {
    if (de->d_name.len == 0) return 0;

    u32 inode = de->d_inode->i_ino;
    u32 *inode_ptr = inodemap.lookup(&inode);
    if(inode_ptr != 0) {
        goto RUN;
    }
    
    return 0;
    RUN:;
        struct data_t data = {};
        // This doesn't work
        const char __user *processname = (char *)PT_REGS_PARM1(ctx);

        struct qstr d_name = de->d_name;
        if (d_name.len == 0)
            return 0;

        bpf_probe_read_kernel(&data.fname, sizeof(data.fname), d_name.name);
        bpf_probe_read_kernel(&data.otype, sizeof(data.otype), OPRN);
        bpf_probe_read_user(&data.pname, sizeof(data.pname), (void *)processname);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.pid = bpf_get_current_pid_tgid();
        data.uid = bpf_get_current_uid_gid();

        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
}


int trace_read(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    char OPRN[10] = "READ";

    if (!(file->f_op->read_iter)) return 0;
    return common(ctx, file->f_path.dentry, OPRN);
}

int trace_write(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    char OPRN[10] = "WRITE";

    if (!(file->f_op->write_iter)) return 0;
    return common(ctx, file->f_path.dentry, OPRN);
}

int trace_rename(struct pt_regs *ctx, struct inode *old_dir,
 struct dentry *old_dentry, struct inode *new_dir,
 struct dentry *new_dentry)
{
    char OPRN[100] = "RENAME";
    return common(ctx, old_dentry, OPRN);
}

int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    char OPRN[10] = "CREATE";
    return common(ctx, dentry, OPRN);
};

int trace_delete(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    char OPRN[10] = "DELETE";
    return common(ctx, dentry, OPRN);
}

/*
// KRETFUNC_PROBE function is triggered on process creation
// Linking it with file operation is hackish
KRETFUNC_PROBE(__x64_sys_openat, struct pt_regs *regs, int ret)
{
    struct data_t data = {};

    const char __user *processname = (char *)PT_REGS_PARM2(regs);

    bpf_probe_read_user(&data.pname, sizeof(data.pname), (void *)processname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.pid = bpf_get_current_pid_tgid();
    data.uid = bpf_get_current_uid_gid();

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
*/