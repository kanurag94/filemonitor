#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>

#define EMBEDDED_LEVELS 2
struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	struct inode	*inode; /* path.dentry.d_inode */
	unsigned int	flags, state;
	unsigned	seq, m_seq, r_seq;
	int		last_type;
	unsigned	depth;
	int		total_link_count;
	struct saved {
		struct path link;
		struct delayed_call done;
		const char *name;
		unsigned seq;
	} *stack, internal[EMBEDDED_LEVELS];
	struct filename	*name;
	struct nameidata *saved;
	unsigned	root_seq;
	int		dfd;
	kuid_t		dir_uid;
	umode_t		dir_mode;
} __randomize_layout;


enum status_type {
    LOOPING,
    COMPLETE
};

#define MAXARG 128
struct data_t {
    u32 pid;
    u32 uid;
    enum status_type status;
    char pname[DNAME_INLINE_LEN];
    char fname[MAXARG];
    char comm[TASK_COMM_LEN];
    char otype[TASK_COMM_LEN];
};


BPF_HASH(inodemap, u32, u32);
BPF_PERF_OUTPUT(events);

// bpf_probe_read_kernel takes bpf ctx, buffer (ptr) and data struct as input
// sends a perf event and returns 1 status
static int send_to_perf(struct pt_regs *ctx, char *ptr, struct data_t *data)
{
    bpf_probe_read_kernel(data->fname, sizeof(data->fname), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

// common function takes dentry and operation name as arguments
// looks up if inode exists in "inodemap" then trace and send event update
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
        data.status = LOOPING;

        // This doesn't work
        const char __user *processname = (char *)PT_REGS_PARM1(ctx);
        struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();

        struct qstr d_name = de->d_name;
        if (d_name.len == 0)
            return 0;

        bpf_probe_read_kernel(&data.otype, sizeof(data.otype), OPRN);
        bpf_probe_read_user(&data.pname, sizeof(data.pname), (void *)processname);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.pid = bpf_get_current_pid_tgid();
        data.uid = bpf_get_current_uid_gid();

        // Loops and create file path
        struct dentry *parent = curr_task->fs->root.dentry;
        int max_depth = 1000;
        while(max_depth && de != parent){
            send_to_perf(ctx, de->d_name.name, &data);
            de = de->d_parent;

            max_depth -= 1;
        }

        data.status = COMPLETE;
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
}

// trace_read function takes file, buffer and size as arguments
// this is attached to file read (vfs_read) events
int trace_read(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    char OPRN[10] = "READ";

    if (!(file->f_op->read_iter)) return 0;
    return common(ctx, file->f_path.dentry, OPRN);
}

// trace_write function takes file, buffer and size as arguments
// this is attached to file write (vfs_read) events
int trace_write(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    char OPRN[10] = "WRITE";

    if (!(file->f_op->write_iter)) return 0;
    return common(ctx, file->f_path.dentry, OPRN);
}

// trace_rename function takes old directory inode,
// old dentry, new directory inode, new dentry as arguments
// this is attached to file rename (vfs_rename) events
int trace_rename(struct pt_regs *ctx, struct inode *old_dir,
 struct dentry *old_dentry, struct inode *new_dir,
 struct dentry *new_dentry)
{
    char OPRN[100] = "RENAME";
    return common(ctx, old_dentry, OPRN);
}

// trace_write function takes old directory inode, dentry as arguments
// this is attached to file create (security_inode_create) events
// vfs_create is not fired by kernel > 4.8
int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    char OPRN[10] = "CREATE";
    return common(ctx, dentry, OPRN);
};

// trace_write function takes old directory inode, dentry as arguments
// this is attached to file unlinking(vfs_unlink) events to trace before deletion
int trace_delete(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    char OPRN[10] = "DELETE";
    return common(ctx, dentry, OPRN);
}

/*
// KRETFUNC_PROBE probe is triggered on process creation
// Linking it with file operation is hackish
// TODO: Link with file events
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
