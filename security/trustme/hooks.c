#include <linux/security.h>
#include <linux/path.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/netlink.h>

#include <linux/pid_namespace.h>

#define TRUSTME_ICC_PATH "/data/trustme-com*"

struct mount_whitelist_entry {
	char *dev_name;
	char *path;
	char *type;
	unsigned long flags_that_matter;
	unsigned long flags;
};

/*************************************
 * Whitelists and Blacklists */

static struct mount_whitelist_entry mount_whitelist[] = {
	/* Allow the container to do arbitrary tmpfs type mounts */
	{"*", "*", "tmpfs", 0, 0},

	/* Allow the container some magic on its rootfs */
	{"*", "/", "rootfs", MS_RDONLY | MS_REMOUNT, MS_RDONLY | MS_REMOUNT},
	{"*", "/", "rootfs", MS_REC | MS_SHARED, MS_REC | MS_SHARED},
	{"*", "/", "*", MS_REC | MS_SLAVE, MS_REC | MS_SLAVE},

	/* Allow the container remounting its /system with some mandatory flags */
	{"*", "/system", "*", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_REMOUNT,
		MS_RDONLY | MS_NOSUID | MS_NODEV | MS_REMOUNT},

	/* Allow the container mounting sysfs and procfs to the default locations (only) */
	{"*", "/sys", "sysfs", 0, 0},
	{"*", "/proc", "procfs", 0, 0},

	/* Allow the container to mount a fuse to a specific folder */
	{"*", "/mnt/shell/emulated", "fuse", 0, 0},
	/* Allow container bind mounts from fuse to storage tmpfs */
	{"/mnt/shell/emulated*", "/storage/emulated*", "*", MS_BIND, MS_BIND},
	/* Allow container bind mounts inside the emulated storage folder */
	{"/storage/emulated*", "/storage/emulated*", "*", MS_BIND, MS_BIND},

	/* Example: Allow all kinds of bind mounts */
	//{"*", "*", "*", MS_BIND, MS_BIND},
	/* Example: Allow all mounts that are NO bind mounts (not very usable rule) */
	//{"*", "*", "*", MS_BIND, 0};
};

static char *trustme_path_whitelist[] = {
	"/",
	"/system*",
	"/data*",
	"/dev*",
	"/proc*",
	"/tmp*",
	"/firmware*",
	"/cache*",
	"/mnt*",
	"/persist*",
	"/storage*",
	"/sbin*",
	"/acct*",

	/* sysfs stuff */
	"/sys",
	"/sys/kernel*",
	"/sys/module*",
	"/sys/power*",
	"/sys/firmware*",
	"/sys/fs*",
	"/sys/bus*",
	"/sys/class*",
	"/sys/dev/*",
	"/sys/devices*",
	//"/sys/devices/virtual*",
	//"/sys/devices/timer*";
	//"/sys/devices/system*",
	//"/sys/devices/soc*",
	//"/sys/devices/qpnp*",
	//"/sys/devices/qcrypto*",
	//"/sys/devices/qcom,*",
	//"/sys/devices/pm8941,*",
	//"/sys/devices/platform*",
	//"/sys/devices/msm*",
	//"/sys/devices/mdp*",
	//"/sys/devices/maxim*",
	//"/sys/devices/l2*",
	//"/sys/devices/keyreset*",
	//"/sys/devices/hall*",
	//"/sys/devices/gpio*",
	//"/sys/devices/earjack*",
	//"/sys/devices/cpu*",
	//"/sys/devices/cpaccess*",
	//"/sys/devices/adcmap*",
	//"/sys/devices/sb*",
	//"/sys/devices/f9*",
	//"/sys/devices/fa*",
	//"/sys/devices/fb*",
	//"/sys/devices/fc*",
	//"/sys/devices/fd*",
	//"/sys/devices/fe*",
	//"/sys/devices/7b*",
	//"/sys/devices/6144*",
	//"/sys/devices/48.*",
	//"/sys/devices/breakpoint*",
	//"/sys/devices/bq51013b_wlc.77*",
	//"/sys/devices/bluesleep.82*",
	//"/sys/devices/battery_tm_ctrl.78*",
	//"/sys/devices/avdd33.79*",
	//"/sys/devices/wcd9xxx-irq.*",
	//"/sys/devices/vibrator.*",
	//"/sys/devices/vdd10.*",
	//"/sys/devices/usb_bam*",
	//"/sys/devices/uei_irrc.*",
	//"/sys/devices/tracepoint*",
	//"/sys/devices/spmi*",
	//"/sys/devices/spi*",
	//"/sys/devices/sound.*",
	//"/sys/devices/software*",
	//"/sys/devices/slimbus*",
	//"/sys/devices/qcedev.*",
	NULL
};

static char *trustme_path_ro_whitelist[] = {
	NULL,
};

static char *trustme_path_blacklist[] = {
	"/sys/devices/leds-*",
	TRUSTME_ICC_PATH,
	NULL,
};


/*************************************
 * Consolidating helper functions   */

static void trustme_pidns_drop_privs(struct pid_namespace *pidns) {
	printk(KERN_INFO "trustme-lsm: Dropping privileges in pid_namespace with child_reaper: %d", task_pid_nr(pidns->child_reaper));
	pidns->security = 1;
}

static bool trustme_pidns_is_privileged(struct pid_namespace *pidns) {
	struct pid_namespace *cur_pid_ns = pidns;

	/* init_pid_ns is allowed to do everything */
	if (pidns == &init_pid_ns)
		return true;

	/* traverse pidns tree and check if it has an unprivileged ancestor */
	do {
		if (cur_pid_ns->security) {
			return false;
		}
	} while ((cur_pid_ns = cur_pid_ns->parent));
	return true;
}

static int trustme_task_decision(struct task_struct *actor, struct task_struct *target)
{
	if (trustme_pidns_is_privileged(task_active_pid_ns(actor)))
		return 0;

	/* prevent communication etc. over container boundaries */
	if (task_active_pid_ns(actor) != task_active_pid_ns(target)) {
		printk(KERN_INFO "trustme-lsm: deny inter-container communication from %s to %s", actor->comm, target->comm);
		return -1;
	}

	return 0;
}

static int dirname_len(char *path)
{
	char *dir = strrchr(path, '/');
	return dir ? dir-path+1 : strlen(path);
}

static bool trustme_path_in_list(char *path, char *list[])
{
	int len;
	int d_len;
	char **entry = list;

	d_len = dirname_len(path);

	while (*entry) {
		len = strlen(*entry);
		if (!strncmp(path, *entry, len - 1)) {
			/* only proceed if the last char is a * or if the basepath matches exactly */
			if ((*entry)[len-1] == '*' || !strncmp(path + len - 1, (*entry) + len - 1, d_len-len)) {
				return true;
			}
		}
		entry++;
	}

	return false;
}

static int trustme_path_decision(struct path *path)
{
	char *buf = NULL;
	char *p;
	unsigned int buf_len = PAGE_SIZE / 2;

	if (trustme_pidns_is_privileged(task_active_pid_ns(current)))
		return 0;

	buf = kmalloc(buf_len, GFP_NOFS);
	if (!buf) {
		panic("trustme-lsm: cannot allocate memory for path");
	}
	p = d_path(path, buf, buf_len);

	/* Filter out all pseudo paths, i.e. paths that do not begin with
	 * a slash. Examples: "socket:", "pipe:", "anon_inode:" */
	if (strncmp(p, "/", 1)) {
		kfree(buf);
		return 0;
	}

	if (trustme_path_in_list(p, trustme_path_blacklist)) {
		goto out;
	}

	if (trustme_path_in_list(p, trustme_path_whitelist)) {
		//printk(KERN_INFO "trustme-lsm: allowing container access to %s\n", p);
		kfree(buf);
		return 0;
	}

out:
	printk(KERN_INFO "trustme-lsm: denying container access to %s\n", p);
	kfree(buf);
	return -1;
}

static int trustme_path_open_decision(struct path *path, int flags)
{
	char *buf = NULL;
	char *p;
	unsigned int buf_len = PAGE_SIZE / 2;

	if (trustme_pidns_is_privileged(task_active_pid_ns(current)))
		return 0;

	buf = kmalloc(buf_len, GFP_NOFS);
	if (!buf) {
		panic("trustme-lsm: cannot allocate memory for path");
	}
	p = d_path(path, buf, buf_len);

	if (trustme_path_in_list(p, trustme_path_blacklist)) {
		goto out;
	}

	if (trustme_path_in_list(p, trustme_path_whitelist)) {
		//printk(KERN_INFO "trustme-lsm: allowing container access to %s\n", p);
		kfree(buf);
		return 0;
	}

	/* additionally check if there are NO flags, i.e. read-only mode and
	 * use the read-only whitelist additionally in this case */
	if (!flags && trustme_path_in_list(p, trustme_path_ro_whitelist)) {
		//printk(KERN_INFO "trustme-lsm: allowing container read-only access to %s\n", p);
		kfree(buf);
		return 0;
	}

out:
	printk(KERN_INFO "trustme-lsm: denying container access to %s\n", p);
	kfree(buf);
	return -1;
}

static int trustme_android_alarm_set_rtc(void)
{
	if (trustme_pidns_is_privileged(task_active_pid_ns(current)))
		return 0;

	printk(KERN_INFO "trustme-lsm: denying unprivileged container to set rtc\n");
	return -1;
}

/*************************************
 * Binder Hooks */
static int trustme_binder_set_context_mgr(struct task_struct *mgr)
{
	//struct pid_namespace *pidns = task_active_pid_ns(mgr);
	//printk(KERN_INFO "trustme-lsm: binder_set_context_mgr called");

	printk(KERN_INFO "trustme-lsm: new context manager %s with pid: %d and vpid: %d",
			mgr->comm, task_pid_nr(mgr), task_pid_vnr(mgr));
	//printk(KERN_INFO "trustme-lsm: child reaper of pidns: %s with pid %d",
	//		pidns->child_reaper->comm, task_pid_nr(pidns->child_reaper));

	return 0;
}

static int trustme_binder_transaction(struct task_struct *from, struct task_struct *to)
{
	//printk(KERN_INFO "binder transaction: from: %s to: %s", from->comm, to->comm);

	/* prevent binder transactions over container boundaries */
	return trustme_task_decision(from, to);
}

static int trustme_binder_transfer_binder(struct task_struct *from, struct task_struct *to)
{
	return trustme_task_decision(from, to);
}

static int trustme_binder_transfer_file(struct task_struct *from, struct task_struct *to, struct file *file)
{
	return trustme_task_decision(from, to);
}

/*************************************
 * BPRM Hooks
 * It is currently quite unclear if we need these */
//static int trustme_bprm_set_creds(struct linux_binprm *bprm) {}
//static int trustme_bprm_check_security(struct linux_binprm *bprm) {}
//static int trustme_bprm_secureexec(struct linux_binprm *bprm) {}
//static void trustme_bprm_committing_creds(struct linux_binprm *bprm) {}
//static void trustme_bprm_committed_creds(struct linux_binprm *bprm) {}

/*************************************
 * Superblock Hooks
 * We definitely need at least the sb_mount callback to restrict mounts for the container
 * e.g. not allowing a container to do a cgroups mount */
//static int trustme_sb_alloc_security(struct super_block *sb);
//static void trustme_sb_free_security(struct super_block *sb);
//static int trustme_sb_copy_data(char *orig, char *copy);
//static int trustme_sb_remount(struct super_block *sb, void *data);
//static int trustme_sb_kern_mount(struct super_block *sb, int flags, void *data);
//static int trustme_sb_show_options(struct seq_file *m, struct super_block *sb);
//static int trustme_sb_statfs(struct dentry *dentry);
//static int trustme_sb_set_mnt_opts(struct super_block *sb,
//                              struct security_mnt_opts *opts);
//static void trustme_sb_clone_mnt_opts(const struct super_block *oldsb,
//                                 struct super_block *newsb);
//static int trustme_sb_parse_opts_str(char *options, struct security_mnt_opts *opts);

static void trustme_sb_printflags(unsigned long flags)
{
	if(flags & MS_RDONLY     ) printk(" MS_RDONLY");
	if(flags & MS_NOSUID     ) printk(" MS_NOSUID");
	if(flags & MS_NODEV      ) printk(" MS_NODEV");
	if(flags & MS_NOEXEC     ) printk(" MS_NOEXEC");
	if(flags & MS_SYNCHRONOUS) printk(" MS_SYNCHRONOUS");
	if(flags & MS_REMOUNT    ) printk(" MS_REMOUNT");
	if(flags & MS_MANDLOCK   ) printk(" MS_MANDLOCK");
	if(flags & MS_DIRSYNC    ) printk(" MS_DIRSYNC");
	if(flags & MS_NOATIME    ) printk(" MS_NOATIME");
	if(flags & MS_NODIRATIME ) printk(" MS_NODIRATIME");
	if(flags & MS_BIND       ) printk(" MS_BIND");
	if(flags & MS_MOVE       ) printk(" MS_MOVE");
	if(flags & MS_REC        ) printk(" MS_REC");
	if(flags & MS_VERBOSE    ) printk(" MS_VERBOSE");
	if(flags & MS_SILENT     ) printk(" MS_SILENT");
	if(flags & MS_POSIXACL   ) printk(" MS_POSIXACL");
	if(flags & MS_UNBINDABLE ) printk(" MS_UNBINDABLE");
	if(flags & MS_PRIVATE    ) printk(" MS_PRIVATE");
	if(flags & MS_SLAVE      ) printk(" MS_SLAVE");
	if(flags & MS_SHARED     ) printk(" MS_SHARED");
	if(flags & MS_RELATIME   ) printk(" MS_RELATIME");
	if(flags & MS_KERNMOUNT  ) printk(" MS_KERNMOUNT");
	if(flags & MS_I_VERSION  ) printk(" MS_I_VERSION");
	if(flags & MS_STRICTATIME) printk(" MS_STRICTATIME");

	/* sb flags are internal to the kernel */
	if(flags & MS_NOSEC ) printk(" MS_NOSEC");
	if(flags & MS_BORN  ) printk(" MS_BORN");
	if(flags & MS_ACTIVE) printk(" MS_ACTIVE");
	if(flags & MS_NOUSER) printk(" MS_NOUSER");
}

static bool trustme_strings_match(char *rule, char *str)
{
	int rule_len;

	/* Everything matches against wildcard rule */
	if (rule[0] == '*')
		return true;

	/* If the rule is no whildcard (see above) and str is null we don't match */
	if (!str)
		return false;

	rule_len = strlen(rule);

	if (!strncmp(str, rule, rule_len - 1)) {
		/* only proceed if the last char is a * or if it matches exactly */
		if (rule[rule_len-1] == '*' || !strcmp(str + rule_len - 1, rule + rule_len - 1)) {
			return true;
		}
	}
	return false;
}

static int trustme_sb_mount(char *dev_name, struct path *path,
                     char *type, unsigned long flags, void *data)
{
	char *buf = NULL;
	char *p;
	unsigned int buf_len = PAGE_SIZE / 2;
	int ret = -1;
	int i;

	if (trustme_pidns_is_privileged(task_active_pid_ns(current))) {
		//printk(KERN_INFO "trustme-lsm: allowing privileged container sb_mount with dev_name: %s, path: %s, type: %s, flags: %lu\n", dev_name, p, type, flags);
		return 0;
	}

	buf = kmalloc(buf_len, GFP_NOFS);
	if (!buf) {
		panic("trustme-lsm: cannot allocate memory for path");
	}
	p = d_path(path, buf, buf_len);

	/* Check if there is matching entry in the whitelist for the mount */
	for (i = 0; i < ARRAY_SIZE(mount_whitelist); i++) {
		struct mount_whitelist_entry *entry = &mount_whitelist[i];
		/* filter based on mount flags
		 * this should be the fastest, so do it first... */
		if ((entry->flags & entry->flags_that_matter) != (flags & entry->flags_that_matter)) {
			continue;
		}
		/* filter based on device name */
		if (!trustme_strings_match(entry->dev_name, dev_name)) {
			continue;
		}
		/* filter based on mount point */
		if (!trustme_strings_match(entry->path, p)) {
			continue;
		}
		/* filter based on fs type */
		if (!trustme_strings_match(entry->type, type)) {
			continue;
		}
		/* if we reached this point, the whitelist entry matches the mount => we allow it */
		ret = 0;
		break;
	}

	if (ret == 0) {
		printk(KERN_INFO "trustme-lsm: allowing unprivileged container sb_mount with dev_name: %s, path: %s, type: %s", dev_name, p, type);
	} else {
		printk(KERN_INFO "trustme-lsm: denying unprivileged container sb_mount with dev_name: %s, path: %s, type: %s", dev_name, p, type);
	}

	printk(" flags:");
	trustme_sb_printflags(flags);
	printk("\n");

	kfree(buf);
	return ret;
}

static int trustme_sb_umount(struct vfsmount *mnt, int flags)
{
	/* TODO allow unprivileged containers only for special cases... */
	return 0;
}
static int trustme_sb_pivotroot(struct path *old_path,
                         struct path *new_path)
{
	/* containers are not allowed to do this */
	if (trustme_pidns_is_privileged(task_active_pid_ns(current)))
		return 0;
	return -1;
}

/*************************************
 * inode Hooks
 * We probably don't need these as we focus on the path hooks. */

static int trustme_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	struct path path = { mnt, dentry };
	return trustme_path_decision(&path);
}

/*************************************
 * path Hooks */
static int trustme_path_unlink(struct path *dir, struct dentry *dentry)
{
	struct path path = { dir->mnt, dentry };
	return trustme_path_decision(&path);
}

int trustme_path_mkdir(struct path *dir, struct dentry *dentry, umode_t mode)
{
	struct path path = { dir->mnt, dentry };
	return trustme_path_decision(&path);
}

int trustme_path_rmdir(struct path *dir, struct dentry *dentry)
{
	struct path path = { dir->mnt, dentry };
	return trustme_path_decision(&path);
}

static int trustme_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,
			   unsigned int dev)
{
	struct path path = { dir->mnt, dentry};
	return trustme_path_decision(&path);
}

int trustme_path_truncate(struct path *path)
{
	return trustme_path_decision(path);
}

int trustme_path_symlink(struct path *dir, struct dentry *dentry,
			  const char *old_name)
{
	struct path path = { dir->mnt, dentry };
	return trustme_path_decision(&path);
}

int trustme_path_link(struct dentry *old_dentry, struct path *new_dir,
		       struct dentry *new_dentry)
{
	struct path path1 = { new_dir->mnt, old_dentry };
	struct path path2 = { new_dir->mnt, new_dentry };
	if (trustme_path_decision(&path1) || trustme_path_decision(&path2))
		return -1;
	return 0;
}

int trustme_path_rename(struct path *old_dir, struct dentry *old_dentry,
			 struct path *new_dir, struct dentry *new_dentry)
{
	struct path path1 = { old_dir->mnt, old_dentry };
	struct path path2 = { new_dir->mnt, new_dentry };
	if (trustme_path_decision(&path1) || trustme_path_decision(&path2))
		return -1;
	return 0;
}

int trustme_path_chmod(struct path *path, umode_t mode)
{
	return trustme_path_decision(path);
}

static int trustme_path_chown(struct path *path, uid_t uid, gid_t gid)
{
	return trustme_path_decision(path);
}

int trustme_path_chroot(struct path *path)
{
	return trustme_path_decision(path);
}

int trustme_dentry_open(struct file *file, const struct cred *cred)
{
	return trustme_path_open_decision(&file->f_path, file->f_flags);
}

/*************************************
 * File Hooks
 * Checks on already open files. */
static int trustme_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return trustme_path_decision(&file->f_path);
}

static int trustme_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return trustme_path_decision(&file->f_path);
}

/*
static int trustme_file_permission(struct file *file, int mask)
{
	return trustme_path_decision(&file->f_path);
}
*/

/*************************************
 * Task Hooks
 * All hooks that access some other task struct should check if the accessed process is in the same namespace 
 * e.g. setpgid, setioprio, setnice, setrlimit, setscheduler, kill, wait */

/*************************************
 * Netlink hook
 * Allows to check single netlink messages. We probably don't need this since we can prevent the container from
 * opening a socket of type netlink via the socket hooks...? */

/*************************************
 * Unix Socket operations
 * These are hooks for sockets in the abstract unix domain socket namespace. Other unix domain sockets can also
 * be handled via normal inode/socket hooks */

/*************************************
 * Socket hooks
 * Some hooks could be interesting: */
int trustme_socket_create(int family, int type, int protocol, int kern)
{
	if (trustme_pidns_is_privileged(task_active_pid_ns(current)))
		return 0;

	if (family == AF_NETLINK && protocol == NETLINK_KOBJECT_UEVENT) {
		printk(KERN_INFO "trustme-lsm: preventing container process %s from opening netlink uevent socket",
				current->comm);
		return -1;
	}

	return 0;
}
//int trustme_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen);
//int trustme_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen);
//int trustme_socket_listen(struct socket *sock, int backlog);
//int trustme_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size);

/*************************************
 * XFRM hooks
 * Something with firewall ops... */

/*************************************
 * Key hooks
 * We probably don't need these */

/*************************************
 * System V IPC hooks (msg_queue_*, ipc_*, shm_*)
 * We have to prevent ipc between processes from different namespaces */

/*************************************
 * System V Semaphores
 * no idea... */

/*************************************
 * Misc Hooks
 * ptrace: only allow if namespaces match
 * capget,capset: only allow if current matches target task namespace
 * ...  */
static int trustme_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
	return trustme_task_decision(current, child);
}

static int trustme_ptrace_traceme(struct task_struct *parent)
{
	return trustme_task_decision(parent, current);
}

static int trustme_capget(struct task_struct *target,
                    kernel_cap_t *effective,
                    kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return trustme_task_decision(current, target);
}

/* We don't need this since it sets caps on the current process. Leave
   this to the default capability checks. */
//static int trustme_capset(struct cred *new,
//                    const struct cred *old,
//                    const kernel_cap_t *effective,
//                    const kernel_cap_t *inheritable,
//                    const kernel_cap_t *permitted);
//static int trustme_capable(const struct cred *cred, struct user_namespace *ns,
//			int cap, int audit);

/* We probably do not need the following */
//static int quotactl(int cmds, int type, int id, struct super_block *sb);
//static int quota_on(struct dentry *dentry);
//static int syslog(int type);
//static int settime(const struct timespec *ts, const struct timezone *tz);
//static int vm_enough_memory(struct mm_struct *mm, long pages);

static struct security_operations trustme_ops = {
	.name =			"trustme",

	/* android alarm */
	.android_alarm_set_rtc = trustme_android_alarm_set_rtc,

	/* binder */
	.binder_set_context_mgr = trustme_binder_set_context_mgr,
	.binder_transaction = trustme_binder_transaction,
	.binder_transfer_binder = trustme_binder_transfer_binder,
	.binder_transfer_file = trustme_binder_transfer_file,

	/* superblock */
	.sb_mount = trustme_sb_mount,
	.sb_umount = trustme_sb_umount,
	.sb_pivotroot = trustme_sb_pivotroot,

	/* path and file */
	.path_unlink = trustme_path_unlink,
	.path_mkdir = trustme_path_mkdir,
	.path_rmdir = trustme_path_rmdir,
	.path_mknod = trustme_path_mknod,
	.path_truncate = trustme_path_truncate,
	.path_symlink = trustme_path_symlink,
	.path_link = trustme_path_link,
	.path_rename = trustme_path_rename,
	.path_chmod = trustme_path_chmod,
	.path_chown = trustme_path_chown,
	.path_chroot = trustme_path_chroot,
	.dentry_open = trustme_dentry_open,
	.file_ioctl = trustme_file_ioctl,
	.file_fcntl = trustme_file_fcntl,
	.inode_getattr = trustme_inode_getattr,
	//.file_permission = trustme_file_permission,
	//.inode_permission = trustme_inode_permission,

	/* socket */
	.socket_create = trustme_socket_create,

	/* misc */
	.ptrace_access_check = trustme_ptrace_access_check,
	.ptrace_traceme = trustme_ptrace_traceme,
	.capget = trustme_capget,
	//.capable = trustme_capable,

};

static __init int trustme_init(void)
{
	/* Normally a module should call this, but we don't, because we want to be 
	 * active in any case and we don't interfere with other modules (no xattr etc.)*/
//	if (!security_module_enable(&trustme_ops))
//		return 0;

	printk(KERN_INFO "trustme-lsm: becoming mindful.\n");

	if (register_security(&trustme_ops))
		panic("trustme-lsm: kernel registration failed.\n");

	return 0;
}
security_initcall(trustme_init);

/*************************************************
 * SecurityFS interface */
static int trustme_droppriv_open(struct inode *inode, struct file *file)
{
	trustme_pidns_drop_privs(task_active_pid_ns(current));
	return 0;
}

/**
 * trustme_operations is a "struct file_operations" which is used for handling
 * /sys/kernel/security/trustme/ interface.
 */
static const struct file_operations trustme_droppriv_fops = {
	.open    = trustme_droppriv_open,
	//.release = trustme_release,
	//.poll    = trustme_poll,
	//.read    = trustme_read,
	//.write   = trustme_write,
	.llseek  = noop_llseek,
};

/**
 * Initialize /sys/kernel/security/trustme/ interface.
 *
 * Returns 0.
 */
static int __init trustme_securityfs_init(void)
{
	struct dentry *trustme_dir;

	trustme_dir = securityfs_create_dir("trustme", NULL);
	securityfs_create_file("drop_privileges", 0600, trustme_dir, NULL,
			       &trustme_droppriv_fops);
	return 0;
}

fs_initcall(trustme_securityfs_init);
