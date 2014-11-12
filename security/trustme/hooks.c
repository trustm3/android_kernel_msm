#include <linux/lsm_hooks.h>
#include <linux/path.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/dcache.h>

#include <linux/pid_namespace.h>

static int trustme_binder_set_context_mgr(struct task_struct *mgr)
{
	struct pid_namespace *pidns = task_active_pid_ns(mgr);
	printk(KERN_INFO "trustme-lsm: binder_set_context_mgr called");

	printk(KERN_INFO "trustme-lsm: new context manager %s with pid: %d and vpid: %d",
			mgr->comm, task_pid_nr(mgr), task_pid_vnr(mgr));
	printk(KERN_INFO "trustme-lsm: child reaper of pidns: %s with pid %d",
			pidns->child_reaper->comm, task_pid_nr(pidns->child_reaper));

	return 0;
}

static int trustme_binder_transaction(struct task_struct *from, struct task_struct *to)
{
	//printk(KERN_INFO "binder transaction: from: %s to: %s", from->comm, to->comm);

	/* prevent binder transactions over container boundaries */
	if (task_active_pid_ns(from) != task_active_pid_ns(to)) {
		printk(KERN_INFO "trustme-lsm: deny inter-container binder communication");
		return -1;
	}
	return 0;
}

static int trustme_inode_permission(struct inode *inode, int mask)
{
	//struct pid_namespace *pidns = task_active_pid_ns(current);

	// TODO check the policy if the pidns may access the inode...
	/*
	struct pid_namespace *pidns = task_active_pid_ns(current);
	pid_t container_init_pid = task_pid_nr(pidns->child_reaper);
	struct super_block *current_root_sb = current->fs->root.mnt->mnt_sb;
	struct super_block *inode_sb = inode->i_sb;
	if (current_root_sb != inode_sb) {
		printk(KERN_INFO "trustme-lsm: container (PID: %d on superblock %s) accessing"
				" inode on superblock %s",
				container_init_pid,
				current_root_sb->s_id,
				inode_sb->s_id);
	}
	*/

	return 0;
}

static int trustme_file_permission(struct file *file, int mask)
{
	return 0;
}

static int trustme_capable(const struct cred *cred, struct user_namespace *ns,
			int cap, int audit)
{
	return 0;
}

static struct security_hook_list trustme_hooks[] = {
	LSM_HOOK_INIT(binder_set_context_mgr, trustme_binder_set_context_mgr),
	LSM_HOOK_INIT(binder_transaction, trustme_binder_transaction),
	LSM_HOOK_INIT(inode_permission, trustme_inode_permission),
	LSM_HOOK_INIT(file_permission, trustme_file_permission),
	LSM_HOOK_INIT(capable, trustme_capable),
};

static __init int trustme_init(void)
{
	/* Normally a module should call this, but we don't, because we want to be
	 * active in any case and we don't interfere with other modules (no xattr etc.)*/
//	if (!security_module_enable("trustme"))
//		return 0;

	printk(KERN_INFO "trustme-lsm: becoming mindful.\n");

	security_add_hooks(trustme_hooks, ARRAY_SIZE(trustme_hooks));
	return 0;
}

security_initcall(trustme_init);
