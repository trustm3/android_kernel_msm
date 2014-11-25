/*
 * security plug functions
 *
 * Copyright (C) 2001 WireX Communications, Inc <chris@wirex.com>
 * Copyright (C) 2001-2002 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2001 Networks Associates Technology, Inc <ssmalley@nai.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 */

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/integrity.h>
#include <linux/ima.h>
#include <linux/evm.h>
#include <linux/fsnotify.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/personality.h>
#include <linux/backing-dev.h>
#include <linux/list.h>
#include <net/flow.h>

/*
 * Generic hook list structure.
 * For use with generic list macros for common operations.
 */
struct security_hook_list {
	struct list_head	list;
	void			*vook;
};

#define MAX_LSM_EVM_XATTR	2

/* Boot-time LSM user choice */
static __initdata char chosen_lsm[SECURITY_NAME_MAX + 1] =
	CONFIG_DEFAULT_SECURITY;

static void __init do_security_initcalls(void)
{
	initcall_t *call;
	call = __security_initcall_start;
	while (call < __security_initcall_end) {
		(*call) ();
		call++;
	}
}

static int __init security_enlist_ops(struct security_operations *sop);

/**
 * security_init - initializes the security framework
 *
 * This should be called early in the kernel initialization sequence.
 */
int __init security_init(void)
{
	int rc;

	pr_info("Security Framework initialized\n");

	/*
	 * Always load the capability module.
	 */
	rc = security_enlist_ops(&capability_ops);
	if (rc)
		return rc;
#ifdef CONFIG_SECURITY_YAMA_STACKED
	rc = security_enlist_ops(&yama_ops);
	if (rc)
		return rc;
#endif
	/*
	 * Load the chosen module if there is one.
	 * This will also find yama if it is stacking
	 */
	do_security_initcalls();

	return 0;
}

/* Save user chosen LSM */
static int __init choose_lsm(char *str)
{
	strncpy(chosen_lsm, str, SECURITY_NAME_MAX);
	return 1;
}
__setup("security=", choose_lsm);

/**
 * security_module_enable - Load given security module on boot ?
 * @ops: a pointer to the struct security_operations that is to be checked.
 *
 * Each LSM must pass this method before registering its own operations
 * to avoid security registration races. This method may also be used
 * to check if your LSM is currently loaded during kernel initialization.
 *
 * Return true if:
 *	-The passed LSM is the one chosen by user at boot time,
 *	-or the passed LSM is configured as the default and the user did not
 *	 choose an alternate LSM at boot time.
 * Otherwise, return false.
 */
int __init security_module_enable(struct security_operations *ops)
{
	return !strcmp(ops->name, chosen_lsm);
}

/**
 * register_security - registers a security framework with the kernel
 * @ops: a pointer to the struct security_options that is to be registered
 *
 * This function allows a security module to register itself with the
 * kernel security subsystem.  Some rudimentary checking is done on the @ops
 * value passed to this function. You'll need to check first if your LSM
 * is allowed to register its @ops by calling security_module_enable(@ops).
 *
 * If there is already a security module registered with the kernel,
 * an error will be returned.  Otherwise %0 is returned on success.
 */
int __init register_security(struct security_operations *ops)
{
	/*
	 * Verify the security_operations structure exists
	 */
	if (!ops) {
		pr_debug("%s could not verify security_operations.\n",
				__func__);
		return -EINVAL;
	}

	return security_enlist_ops(ops);
}

/*
 * Hook list operation macros.
 *
 * call_void_hook:
 *	This is a hook that does not return a value.
 *
 * call_int_hook:
 *	This is a hook that returns a value.
 *	Stop on the first failure.
 *	Returns 2nd argument (usually 0) if no module uses the hook.
 */

#define call_void_hook(FUNC, ...)					\
	do {								\
		struct lsm_##FUNC *P;					\
									\
		list_for_each_entry(P, &hooks_##FUNC, list)		\
			P->hook(__VA_ARGS__);				\
	} while (0)

#define call_int_hook(FUNC, IRC, ...) ({				\
	int RC = IRC;							\
	do {								\
		struct lsm_##FUNC *P;					\
									\
		list_for_each_entry(P, &hooks_##FUNC, list) {		\
			RC = P->hook(__VA_ARGS__);			\
			if (RC != 0)					\
				break;					\
		}							\
	} while (0);							\
	RC;								\
})

/*
 * Macros for hook lists.
 * HOOK_HEAD defines a hook list and the structure to go with it.
 * HOOK does the same, and the function declaration.
 *
 * HOOK_HEAD gets used when there are naming or parameter differences
 * between security_hook and module_hook.
 */
#define HOOK_HEAD(TIPE, FUNC, ...)	\
static LIST_HEAD(hooks_##FUNC);		\
struct lsm_##FUNC {			\
	struct list_head list;		\
	TIPE (*hook)(__VA_ARGS__);	\
}

#define HOOK(TIPE, FUNC, ...)		\
static LIST_HEAD(hooks_##FUNC);		\
struct lsm_##FUNC {			\
	struct list_head list;		\
	TIPE (*hook)(__VA_ARGS__);	\
};					\
TIPE security_##FUNC(__VA_ARGS__)

/* Security operations */

HOOK(int, binder_set_context_mgr, struct task_struct *mgr)
{
	return call_int_hook(binder_set_context_mgr, 0, mgr);
}

HOOK(int, binder_transaction, struct task_struct *from, struct task_struct *to)
{
	return call_int_hook(binder_transaction, 0, from, to);
}

HOOK(int, binder_transfer_binder, struct task_struct *from, struct task_struct *to)
{
	return call_int_hook(binder_transfer_binder, 0, from, to);
}

HOOK(int, binder_transfer_file, struct task_struct *from, struct task_struct *to, struct file *file)
{
	return call_int_hook(binder_transfer_file, 0, from, to, file);
}

HOOK(int, ptrace_access_check, struct task_struct *child, unsigned int mode)
{
	return call_int_hook(ptrace_access_check, 0, child, mode);
}

HOOK(int, ptrace_traceme, struct task_struct *parent)
{
	return call_int_hook(ptrace_traceme, 0, parent);
}

HOOK(int, capget, struct task_struct *target, kernel_cap_t *effective,
	kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return call_int_hook(capget, 0, target, effective, inheritable,
				permitted);
}

HOOK(int, capset, struct cred *new, const struct cred *old,
	const kernel_cap_t *effective, const kernel_cap_t *inheritable,
	const kernel_cap_t *permitted)
{
	return call_int_hook(capset, 0, new, old, effective, inheritable,
				permitted);
}

HOOK_HEAD(int, capable, const struct cred *cred, struct user_namespace *ns,
		int cap, int ad);
int security_capable(const struct cred *cred, struct user_namespace *ns,
			int cap)
{
	return call_int_hook(capable, 0, cred, ns, cap, SECURITY_CAP_AUDIT);
}

/*
 * This is special because there is no capable_noaudit
 * the the hooks list
 */
int security_capable_noaudit(const struct cred *cred,
				struct user_namespace *ns, int cap)
{
	return call_int_hook(capable, 0, cred, ns, cap, SECURITY_CAP_NOAUDIT);
}

HOOK(int, quotactl, int cmds, int type, int id, struct super_block *sb)
{
	return call_int_hook(quotactl, 0, cmds, type, id, sb);
}

HOOK(int, quota_on, struct dentry *dentry)
{
	return call_int_hook(quota_on, 0, dentry);
}

HOOK(int, syslog, int type)
{
	return call_int_hook(syslog, 0, type);
}

HOOK(int, settime, const struct timespec *ts, const struct timezone *tz)
{
	return call_int_hook(settime, 0, ts, tz);
}

HOOK_HEAD(int, vm_enough_memory, struct mm_struct *mm, long pages);
int security_vm_enough_memory_mm(struct mm_struct *mm, long pages)
{
	struct lsm_vm_enough_memory *hp;
	int cap_sys_admin = 1;
	int rc;

	/*
	 * The module will respond with a positive value if
	 * it thinks the __vm_enough_memory() call should be
	 * made with the cap_sys_admin set. If all of the modules
	 * agree that it should be set it will. If any module
	 * thinks it should not be set it won't.
	 */
	list_for_each_entry(hp, &hooks_vm_enough_memory, list) {
		rc = hp->hook(mm, pages);
		if (rc <= 0) {
			cap_sys_admin = 0;
			break;
		}
	}
	return __vm_enough_memory(mm, pages, cap_sys_admin);
}

HOOK(int, bprm_set_creds, struct linux_binprm *bprm)
{
	return call_int_hook(bprm_set_creds, 0, bprm);
}

HOOK_HEAD(int, bprm_check_security, struct linux_binprm *bprm);
int security_bprm_check(struct linux_binprm *bprm)
{
	int ret;

	ret = call_int_hook(bprm_check_security, 0, bprm);
	if (ret)
		return ret;
	return ima_bprm_check(bprm);
}

HOOK(void, bprm_committing_creds, struct linux_binprm *bprm)
{
	call_void_hook(bprm_committing_creds, bprm);
}

HOOK(void, bprm_committed_creds, struct linux_binprm *bprm)
{
	call_void_hook(bprm_committed_creds, bprm);
}

HOOK(int, bprm_secureexec, struct linux_binprm *bprm)
{
	return call_int_hook(bprm_secureexec, 0, bprm);
}

HOOK_HEAD(int, sb_alloc_security, struct super_block *sb);
int security_sb_alloc(struct super_block *sb)
{
	return call_int_hook(sb_alloc_security, 0, sb);
}

HOOK_HEAD(void, sb_free_security, struct super_block *sb);
void security_sb_free(struct super_block *sb)
{
	call_void_hook(sb_free_security, sb);
}

HOOK(int, sb_copy_data, char *orig, char *copy)
{
	return call_int_hook(sb_copy_data, 0, orig, copy);
}
EXPORT_SYMBOL(security_sb_copy_data);

HOOK(int, sb_remount, struct super_block *sb, void *data)
{
	return call_int_hook(sb_remount, 0, sb, data);
}

HOOK(int, sb_kern_mount, struct super_block *sb, int flags, void *data)
{
	return call_int_hook(sb_kern_mount, 0, sb, flags, data);
}

HOOK(int, sb_show_options, struct seq_file *m, struct super_block *sb)
{
	return call_int_hook(sb_show_options, 0, m, sb);
}

HOOK(int, sb_statfs, struct dentry *dentry)
{
	return call_int_hook(sb_statfs, 0, dentry);
}

HOOK(int, sb_mount, const char *dev_name, struct path *path,
                       const char *type, unsigned long flags, void *data)
{
	return call_int_hook(sb_mount, 0, dev_name, path, type, flags, data);
}

HOOK(int, sb_umount, struct vfsmount *mnt, int flags)
{
	return call_int_hook(sb_umount, 0, mnt, flags);
}

HOOK(int, sb_pivotroot, struct path *old_path, struct path *new_path)
{
	return call_int_hook(sb_pivotroot, 0, old_path, new_path);
}

HOOK(int, sb_set_mnt_opts, struct super_block *sb,
				struct security_mnt_opts *opts)
{
	return call_int_hook(sb_set_mnt_opts,
				opts->num_mnt_opts ? -EOPNOTSUPP : 0, sb, opts);
}
EXPORT_SYMBOL(security_sb_set_mnt_opts);

HOOK(void, sb_clone_mnt_opts, const struct super_block *oldsb,
	struct super_block *newsb)
{
	call_void_hook(sb_clone_mnt_opts, oldsb, newsb);
}
EXPORT_SYMBOL(security_sb_clone_mnt_opts);

HOOK(int, sb_parse_opts_str, char *options, struct security_mnt_opts *opts)
{
	return call_int_hook(sb_parse_opts_str, 0, options, opts);
}
EXPORT_SYMBOL(security_sb_parse_opts_str);

HOOK_HEAD(int, inode_alloc_security, struct inode *inode);
int security_inode_alloc(struct inode *inode)
{
	inode->i_security = NULL;
	return call_int_hook(inode_alloc_security, 0, inode);
}

HOOK_HEAD(void, inode_free_security, struct inode *inode);
void security_inode_free(struct inode *inode)
{
	integrity_inode_free(inode);
	call_void_hook(inode_free_security, inode);
}

HOOK_HEAD(int, inode_init_security, struct inode *inode, struct inode *dir,
				     const struct qstr *qstr, char **name,
				     void **value, size_t *len);

int security_inode_init_security(struct inode *inode, struct inode *dir,
					const struct qstr *qstr,
					const initxattrs initxattrs,
					void *fs_data)
{
	struct xattr new_xattrs[MAX_LSM_EVM_XATTR + 1];
	struct xattr *lsm_xattr, *evm_xattr, *xattr;
	int ret;

	if (unlikely(IS_PRIVATE(inode)))
		return 0;

	if (!initxattrs)
		return call_int_hook(inode_init_security, 0, inode, dir, qstr,
					NULL, NULL, NULL);

	memset(new_xattrs, 0, sizeof(new_xattrs));
	lsm_xattr = new_xattrs;

	ret = call_int_hook(inode_init_security, -EOPNOTSUPP, inode, dir,
				qstr, &lsm_xattr->name, &lsm_xattr->value,
				&lsm_xattr->value_len);
	if (ret)
		goto out;

	evm_xattr = lsm_xattr + 1;
	ret = evm_inode_init_security(inode, lsm_xattr, evm_xattr);
	if (ret)
		goto out;
	ret = initxattrs(inode, new_xattrs, fs_data);
out:
	for (xattr = new_xattrs; xattr->name != NULL; xattr++) {
		kfree(xattr->name);
		kfree(xattr->value);
	}
	return (ret == -EOPNOTSUPP) ? 0 : ret;
}
EXPORT_SYMBOL(security_inode_init_security);

/*
 * Shares a hook with inode_init_security
 */
int security_old_inode_init_security(struct inode *inode, struct inode *dir,
				     const struct qstr *qstr, char **name,
				     void **value, size_t *len)
{
	if (unlikely(IS_PRIVATE(inode)))
		return -EOPNOTSUPP;

	return call_int_hook(inode_init_security, 0, inode, dir, qstr, name,
				value, len);
}
EXPORT_SYMBOL(security_old_inode_init_security);

#ifdef CONFIG_SECURITY_PATH
HOOK(int, path_mknod, struct path *dir, struct dentry *dentry, umode_t mode,
	unsigned int dev)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_mknod, 0, dir, dentry, mode, dev);
}
EXPORT_SYMBOL(security_path_mknod);

HOOK(int, path_mkdir, struct path *dir, struct dentry *dentry, umode_t mode)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_mkdir, 0, dir, dentry, mode);
}
EXPORT_SYMBOL(security_path_mkdir);

HOOK(int, path_rmdir, struct path *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_rmdir, 0, dir, dentry);
}

HOOK(int, path_unlink, struct path *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_unlink, 0, dir, dentry);
}
EXPORT_SYMBOL(security_path_unlink);

HOOK(int, path_symlink, struct path *dir, struct dentry *dentry,
	const char *old_name)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_symlink, 0, dir, dentry, old_name);
}

HOOK(int, path_link, struct dentry *old_dentry, struct path *new_dir,
	struct dentry *new_dentry)
{
	if (unlikely(IS_PRIVATE(old_dentry->d_inode)))
		return 0;
	return call_int_hook(path_link, 0, old_dentry, new_dir, new_dentry);
}

HOOK_HEAD(int, path_rename, struct path *old_dir, struct dentry *old_dentry,
		struct path *new_dir, struct dentry *new_dentry);
int security_path_rename(struct path *old_dir, struct dentry *old_dentry,
			 struct path *new_dir, struct dentry *new_dentry)
{
	if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
	    (new_dentry->d_inode && IS_PRIVATE(new_dentry->d_inode))))
		return 0;
	return call_int_hook(path_rename, 0, old_dir, old_dentry, new_dir,
				new_dentry);
}
EXPORT_SYMBOL(security_path_rename);

HOOK(int, path_truncate, struct path *path)
{
	if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
		return 0;
	return call_int_hook(path_truncate, 0, path);
}

HOOK(int, path_chmod, struct path *path, umode_t mode)
{
	if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
		return 0;
	return call_int_hook(path_chmod, 0, path, mode);
}

HOOK(int, path_chown, struct path *path, uid_t uid, gid_t gid)
{
	if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
		return 0;
	return call_int_hook(path_chown, 0, path, uid, gid);
}

HOOK(int, path_chroot, struct path *path)
{
	return call_int_hook(path_chroot, 0, path);
}
#endif

HOOK(int, inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return call_int_hook(inode_create, 0, dir, dentry, mode);
}
EXPORT_SYMBOL_GPL(security_inode_create);

HOOK(int, inode_link, struct dentry *old_dentry, struct inode *dir,
	struct dentry *new_dentry)
{
	if (unlikely(IS_PRIVATE(old_dentry->d_inode)))
		return 0;
	return call_int_hook(inode_link, 0, old_dentry, dir, new_dentry);
}

HOOK(int, inode_unlink, struct inode *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_unlink, 0, dir, dentry);
}

HOOK(int, inode_symlink, struct inode *dir, struct dentry *dentry,
	const char *old_name)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return call_int_hook(inode_symlink, 0, dir, dentry, old_name);
}

HOOK(int, inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return call_int_hook(inode_mkdir, 0, dir, dentry, mode);
}
EXPORT_SYMBOL_GPL(security_inode_mkdir);

HOOK(int, inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_rmdir, 0, dir, dentry);
}

HOOK(int, inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode,
	dev_t dev)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return call_int_hook(inode_mknod, 0, dir, dentry, mode, dev);
}

HOOK_HEAD(int, inode_rename, struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry);
int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
	if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
	    (new_dentry->d_inode && IS_PRIVATE(new_dentry->d_inode))))
		return 0;
	return call_int_hook(inode_rename, 0, old_dir, old_dentry,
				new_dir, new_dentry);
}

HOOK(int, inode_readlink, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_readlink, 0, dentry);
}

HOOK(int, inode_follow_link, struct dentry *dentry, struct nameidata *nd)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_follow_link, 0, dentry, nd);
}

HOOK(int, inode_permission, struct inode *inode, int mask)
{
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	return call_int_hook(inode_permission, 0, inode, mask);
}

HOOK(int, inode_setattr, struct dentry *dentry, struct iattr *attr)
{
	int ret;

	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	ret = call_int_hook(inode_setattr, 0, dentry, attr);
	if (ret)
		return ret;
	return evm_inode_setattr(dentry, attr);
}
EXPORT_SYMBOL_GPL(security_inode_setattr);

HOOK(int, inode_getattr, struct vfsmount *mnt, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_getattr, 0, mnt, dentry);
}

HOOK(int, inode_setxattr, struct dentry *dentry, const char *name,
			    const void *value, size_t size, int flags)
{
	int ret;

	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	/*
	 * SELinux and Smack integrate the cap call,
	 * so assume that all LSMs supplying this call do so.
	 */
	ret = call_int_hook(inode_setxattr, 1, dentry, name, value, size,
				flags);
	if (ret == 1)
		ret = cap_inode_setxattr(dentry, name, value, size, flags);
	if (ret)
		return ret;
	return evm_inode_setxattr(dentry, name, value, size);
}

HOOK(void, inode_post_setxattr, struct dentry *dentry, const char *name,
	const void *value, size_t size, int flags)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return;
	call_void_hook(inode_post_setxattr, dentry, name, value, size, flags);
	evm_inode_post_setxattr(dentry, name, value, size);
}

HOOK(int, inode_getxattr, struct dentry *dentry, const char *name)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_getxattr, 0, dentry, name);
}

HOOK(int, inode_listxattr, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_listxattr, 0, dentry);
}

HOOK(int, inode_removexattr, struct dentry *dentry, const char *name)
{
	int ret;

	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	/*
	 * SELinux and Smack integrate the cap call,
	 * so assume that all LSMs supplying this call do so.
	 */
	ret = call_int_hook(inode_removexattr, 1, dentry, name);
	if (ret == 1)
		ret = cap_inode_removexattr(dentry, name);
	if (ret)
		return ret;
	return evm_inode_removexattr(dentry, name);
}

HOOK(int, inode_need_killpriv, struct dentry *dentry)
{
	return call_int_hook(inode_need_killpriv, 0, dentry);
}

HOOK(int, inode_killpriv, struct dentry *dentry)
{
	return call_int_hook(inode_killpriv, 0, dentry);
}

HOOK(int, inode_getsecurity, const struct inode *inode, const char *name,
	void **buffer, bool alloc)
{
	if (unlikely(IS_PRIVATE(inode)))
		return -EOPNOTSUPP;
	return call_int_hook(inode_getsecurity, -EOPNOTSUPP, inode, name,
				buffer, alloc);
}

HOOK(int, inode_setsecurity, struct inode *inode, const char *name,
	const void *value, size_t size, int flags)
{
	if (unlikely(IS_PRIVATE(inode)))
		return -EOPNOTSUPP;
	return call_int_hook(inode_setsecurity, -EOPNOTSUPP, inode, name,
				value, size, flags);
}

HOOK(int, inode_listsecurity, struct inode *inode, char *buffer,
	size_t buffer_size)
{
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	return call_int_hook(inode_listsecurity, 0, inode, buffer, buffer_size);
}

HOOK(void, inode_getsecid, const struct inode *inode, u32 *secid)
{
	*secid = 0;
	call_void_hook(inode_getsecid, inode, secid);
}

HOOK(int, file_permission, struct file *file, int mask)
{
	int ret;

	ret = call_int_hook(file_permission, 0, file, mask);
	if (ret)
		return ret;

	return fsnotify_perm(file, mask);
}

HOOK_HEAD(int, file_alloc_security, struct file *file);
int security_file_alloc(struct file *file)
{
	return call_int_hook(file_alloc_security, 0, file);
}

HOOK_HEAD(void, file_free_security, struct file *file);
void security_file_free(struct file *file)
{
	call_void_hook(file_free_security, file);
}

HOOK(int, file_ioctl, struct file *file, unsigned int cmd, unsigned long arg)
{
	return call_int_hook(file_ioctl, 0, file, cmd, arg);
}

HOOK_HEAD(int, file_mmap, struct file *file, unsigned long reqprot,
			unsigned long prot, unsigned long flags,
			unsigned long addr, unsigned long addr_only);
int security_file_mmap(struct file *file, unsigned long reqprot,
			unsigned long prot, unsigned long flags,
			unsigned long addr, unsigned long addr_only)
{
	int ret;

	ret = call_int_hook(file_mmap, 0, file, reqprot, prot, flags, addr,
				addr_only);
	if (ret)
		return ret;
	return ima_file_mmap(file, prot);
}

HOOK(int, file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
	unsigned long prot)
{
	return call_int_hook(file_mprotect, 0, vma, reqprot, prot);
}

HOOK(int, file_lock, struct file *file, unsigned int cmd)
{
	return call_int_hook(file_lock, 0, file, cmd);
}

HOOK(int, file_fcntl, struct file *file, unsigned int cmd, unsigned long arg)
{
	return call_int_hook(file_fcntl, 0, file, cmd, arg);
}

HOOK(int, file_set_fowner, struct file *file)
{
	return call_int_hook(file_set_fowner, 0, file);
}

HOOK(int, file_send_sigiotask, struct task_struct *tsk,
	struct fown_struct *fown, int sig)
{
	return call_int_hook(file_send_sigiotask, 0, tsk, fown, sig);
}

HOOK(int, file_receive, struct file *file)
{
	return call_int_hook(file_receive, 0, file);
}

HOOK(int, dentry_open, struct file *file, const struct cred *cred)
{
	int ret;

	ret = call_int_hook(dentry_open, 0, file, cred);
	if (ret)
		return ret;

	return fsnotify_perm(file, MAY_OPEN);
}

HOOK(int, task_create, unsigned long clone_flags)
{
	return call_int_hook(task_create, 0, clone_flags);
}

HOOK(void, task_free, struct task_struct *task)
{
	call_void_hook(task_free, task);
}

HOOK(int, cred_alloc_blank, struct cred *cred, gfp_t gfp)
{
	return call_int_hook(cred_alloc_blank, 0, cred, gfp);
}

HOOK(void, cred_free, struct cred *cred)
{
	call_void_hook(cred_free, cred);
}

HOOK_HEAD(int, cred_prepare, struct cred *new, const struct cred *old,
		gfp_t gfp);
int security_prepare_creds(struct cred *new, const struct cred *old, gfp_t gfp)
{
	return call_int_hook(cred_prepare, 0, new, old, gfp);
}

HOOK_HEAD(void, cred_transfer, struct cred *new, const struct cred *old);
void security_transfer_creds(struct cred *new, const struct cred *old)
{
	call_void_hook(cred_transfer, new, old);
}

HOOK(int, kernel_act_as, struct cred *new, u32 secid)
{
	return call_int_hook(kernel_act_as, 0, new, secid);
}

HOOK(int, kernel_create_files_as, struct cred *new, struct inode *inode)
{
	return call_int_hook(kernel_create_files_as, 0, new, inode);
}

HOOK(int, kernel_module_request, char *kmod_name)
{
	return call_int_hook(kernel_module_request, 0, kmod_name);
}

HOOK(int, task_fix_setuid, struct cred *new, const struct cred *old,
	int flags)
{
	return call_int_hook(task_fix_setuid, 0, new, old, flags);
}

HOOK(int, task_setpgid, struct task_struct *p, pid_t pgid)
{
	return call_int_hook(task_setpgid, 0, p, pgid);
}

HOOK(int, task_getpgid, struct task_struct *p)
{
	return call_int_hook(task_getpgid, 0, p);
}

HOOK(int, task_getsid, struct task_struct *p)
{
	return call_int_hook(task_getsid, 0, p);
}

HOOK(void, task_getsecid, struct task_struct *p, u32 *secid)
{
	*secid = 0;
	call_void_hook(task_getsecid, p, secid);
}
EXPORT_SYMBOL(security_task_getsecid);

HOOK(int, task_setnice, struct task_struct *p, int nice)
{
	return call_int_hook(task_setnice, 0, p, nice);
}

HOOK(int, task_setioprio, struct task_struct *p, int ioprio)
{
	return call_int_hook(task_setioprio, 0, p, ioprio);
}

HOOK(int, task_getioprio, struct task_struct *p)
{
	return call_int_hook(task_getioprio, 0, p);
}

HOOK(int, task_setrlimit, struct task_struct *p, unsigned int resource,
	struct rlimit *new_rlim)
{
	return call_int_hook(task_setrlimit, 0, p, resource, new_rlim);
}

HOOK(int, task_setscheduler, struct task_struct *p)
{
	return call_int_hook(task_setscheduler, 0, p);
}

HOOK(int, task_getscheduler, struct task_struct *p)
{
	return call_int_hook(task_getscheduler, 0, p);
}

HOOK(int, task_movememory, struct task_struct *p)
{
	return call_int_hook(task_movememory, 0, p);
}

HOOK(int, task_kill, struct task_struct *p, struct siginfo *info, int sig,
	u32 secid)
{
	return call_int_hook(task_kill, 0, p, info, sig, secid);
}

HOOK(int, task_wait, struct task_struct *p)
{
	return call_int_hook(task_wait, 0, p);
}

HOOK(int, task_prctl, int option, unsigned long arg2, unsigned long arg3,
	unsigned long arg4, unsigned long arg5)
{
	int thisrc;
	int rc = -ENOSYS;
	struct lsm_task_prctl *hp;

	list_for_each_entry(hp, &hooks_task_prctl, list) {
		thisrc = hp->hook(option, arg2, arg3, arg4, arg5);
		if (thisrc != -ENOSYS) {
			rc = thisrc;
			if (thisrc != 0)
				break;
		}
	}
	return rc;
}

HOOK(void, task_to_inode, struct task_struct *p, struct inode *inode)
{
	call_void_hook(task_to_inode, p, inode);
}

HOOK(int, ipc_permission, struct kern_ipc_perm *ipcp, short flag)
{
	return call_int_hook(ipc_permission, 0, ipcp, flag);
}

HOOK(void, ipc_getsecid, struct kern_ipc_perm *ipcp, u32 *secid)
{
	*secid = 0;
	call_void_hook(ipc_getsecid, ipcp, secid);
}

HOOK_HEAD(int, msg_msg_alloc_security, struct msg_msg *msg);
int security_msg_msg_alloc(struct msg_msg *msg)
{
	return call_int_hook(msg_msg_alloc_security, 0, msg);
}

HOOK_HEAD(void, msg_msg_free_security, struct msg_msg *msg);
void security_msg_msg_free(struct msg_msg *msg)
{
	call_void_hook(msg_msg_free_security, msg);
}

HOOK_HEAD(int, msg_queue_alloc_security, struct msg_queue *msq);
int security_msg_queue_alloc(struct msg_queue *msq)
{
	return call_int_hook(msg_queue_alloc_security, 0, msq);
}

HOOK_HEAD(void, msg_queue_free_security, struct msg_queue *msq);
void security_msg_queue_free(struct msg_queue *msq)
{
	call_void_hook(msg_queue_free_security, msq);
}

HOOK(int, msg_queue_associate, struct msg_queue *msq, int msqflg)
{
	return call_int_hook(msg_queue_associate, 0, msq, msqflg);
}

HOOK(int, msg_queue_msgctl, struct msg_queue *msq, int cmd)
{
	return call_int_hook(msg_queue_msgctl, 0, msq, cmd);
}

HOOK(int, msg_queue_msgsnd, struct msg_queue *msq, struct msg_msg *msg,
	int msqflg)
{
	return call_int_hook(msg_queue_msgsnd, 0, msq, msg, msqflg);
}

HOOK(int, msg_queue_msgrcv, struct msg_queue *msq, struct msg_msg *msg,
	struct task_struct *target, long type, int mode)
{
	return call_int_hook(msg_queue_msgrcv, 0, msq, msg, target, type, mode);
}

HOOK_HEAD(int, shm_alloc_security, struct shmid_kernel *shp);
int security_shm_alloc(struct shmid_kernel *shp)
{
	return call_int_hook(shm_alloc_security, 0, shp);
}

HOOK_HEAD(void, shm_free_security, struct shmid_kernel *shp);
void security_shm_free(struct shmid_kernel *shp)
{
	call_void_hook(shm_free_security, shp);
}

HOOK(int, shm_associate, struct shmid_kernel *shp, int shmflg)
{
	return call_int_hook(shm_associate, 0, shp, shmflg);
}

HOOK(int, shm_shmctl, struct shmid_kernel *shp, int cmd)
{
	return call_int_hook(shm_shmctl, 0, shp, cmd);
}

HOOK(int, shm_shmat, struct shmid_kernel *shp, char __user *shmaddr, int shmflg)
{
	return call_int_hook(shm_shmat, 0, shp, shmaddr, shmflg);
}

HOOK_HEAD(int, sem_alloc_security, struct sem_array *sma);
int security_sem_alloc(struct sem_array *sma)
{
	return call_int_hook(sem_alloc_security, 0, sma);
}

HOOK_HEAD(void, sem_free_security, struct sem_array *sma);
void security_sem_free(struct sem_array *sma)
{
	call_void_hook(sem_free_security, sma);
}

HOOK(int, sem_associate, struct sem_array *sma, int semflg)
{
	return call_int_hook(sem_associate, 0, sma, semflg);
}

HOOK(int, sem_semctl, struct sem_array *sma, int cmd)
{
	return call_int_hook(sem_semctl, 0, sma, cmd);
}

HOOK(int, sem_semop, struct sem_array *sma, struct sembuf *sops,
	unsigned nsops, int alter)
{
	return call_int_hook(sem_semop, 0, sma, sops, nsops, alter);
}

HOOK(void, d_instantiate, struct dentry *dentry, struct inode *inode)
{
	if (unlikely(inode && IS_PRIVATE(inode)))
		return;
	call_void_hook(d_instantiate, dentry, inode);
}
EXPORT_SYMBOL(security_d_instantiate);

HOOK(int, getprocattr, struct task_struct *p, char *name, char **value)
{
	return call_int_hook(getprocattr, -EINVAL, p, name, value);
}

HOOK(int, setprocattr, struct task_struct *p, char *name, void *value,
	size_t size)
{
	return call_int_hook(setprocattr, -EINVAL, p, name, value, size);
}

HOOK(int, netlink_send, struct sock *sk, struct sk_buff *skb)
{
	return call_int_hook(netlink_send, 0, sk, skb);
}

HOOK(int, secid_to_secctx, u32 secid, char **secdata, u32 *seclen)
{
	return call_int_hook(secid_to_secctx, -EOPNOTSUPP, secid, secdata,
				seclen);
}
EXPORT_SYMBOL(security_secid_to_secctx);

HOOK(int, secctx_to_secid, const char *secdata, u32 seclen, u32 *secid)
{
	*secid = 0;
	return call_int_hook(secctx_to_secid, 0, secdata, seclen, secid);
}
EXPORT_SYMBOL(security_secctx_to_secid);

HOOK(void, release_secctx, char *secdata, u32 seclen)
{
	call_void_hook(release_secctx, secdata, seclen);
}
EXPORT_SYMBOL(security_release_secctx);

HOOK(int, inode_notifysecctx, struct inode *inode, void *ctx, u32 ctxlen)
{
	return call_int_hook(inode_notifysecctx, 0, inode, ctx, ctxlen);
}
EXPORT_SYMBOL(security_inode_notifysecctx);

HOOK(int, inode_setsecctx, struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return call_int_hook(inode_setsecctx, 0, dentry, ctx, ctxlen);
}
EXPORT_SYMBOL(security_inode_setsecctx);

HOOK(int, inode_getsecctx, struct inode *inode, void **ctx, u32 *ctxlen)
{
	return call_int_hook(inode_getsecctx, -EOPNOTSUPP, inode, ctx,
				ctxlen);
}
EXPORT_SYMBOL(security_inode_getsecctx);

#ifdef CONFIG_SECURITY_NETWORK

HOOK(int, unix_stream_connect, struct sock *sock, struct sock *other,
	struct sock *newsk)
{
	return call_int_hook(unix_stream_connect, 0, sock, other, newsk);
}
EXPORT_SYMBOL(security_unix_stream_connect);

HOOK(int, unix_may_send, struct socket *sock,  struct socket *other)
{
	return call_int_hook(unix_may_send, 0, sock, other);
}
EXPORT_SYMBOL(security_unix_may_send);

HOOK(int, socket_create, int family, int type, int protocol, int kern)
{
	return call_int_hook(socket_create, 0, family, type, protocol, kern);
}

HOOK(int, socket_post_create, struct socket *sock, int family, int type,
	int protocol, int kern)
{
	return call_int_hook(socket_post_create, 0, sock, family, type,
				protocol, kern);
}

HOOK(int, socket_bind, struct socket *sock, struct sockaddr *address,
	int addrlen)
{
	return call_int_hook(socket_bind, 0, sock, address, addrlen);
}

HOOK(int, socket_connect, struct socket *sock, struct sockaddr *address,
	int addrlen)
{
	return call_int_hook(socket_connect, 0, sock, address, addrlen);
}

HOOK(int, socket_listen, struct socket *sock, int backlog)
{
	return call_int_hook(socket_listen, 0, sock, backlog);
}

HOOK(int, socket_accept, struct socket *sock, struct socket *newsock)
{
	return call_int_hook(socket_accept, 0, sock, newsock);
}

HOOK(int, socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
	return call_int_hook(socket_sendmsg, 0, sock, msg, size);
}

HOOK(int, socket_recvmsg, struct socket *sock, struct msghdr *msg, int size,
	int flags)
{
	return call_int_hook(socket_recvmsg, 0, sock, msg, size, flags);
}

HOOK(int, socket_getsockname, struct socket *sock)
{
	return call_int_hook(socket_getsockname, 0, sock);
}

HOOK(int, socket_getpeername, struct socket *sock)
{
	return call_int_hook(socket_getpeername, 0, sock);
}

HOOK(int, socket_getsockopt, struct socket *sock, int level, int optname)
{
	return call_int_hook(socket_getsockopt, 0, sock, level, optname);
}

HOOK(int, socket_setsockopt, struct socket *sock, int level, int optname)
{
	return call_int_hook(socket_setsockopt, 0, sock, level, optname);
}

HOOK(int, socket_shutdown, struct socket *sock, int how)
{
	return call_int_hook(socket_shutdown, 0, sock, how);
}

HOOK_HEAD(int, socket_sock_rcv_skb, struct sock *sk, struct sk_buff *skb);
int security_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return call_int_hook(socket_sock_rcv_skb, 0, sk, skb);
}
EXPORT_SYMBOL(security_sock_rcv_skb);

HOOK(int, socket_getpeersec_stream, struct socket *sock, char __user *optval,
	int __user *optlen, unsigned len)
{
	return call_int_hook(socket_getpeersec_stream, -ENOPROTOOPT, sock,
				optval, optlen, len);
}

HOOK(int, socket_getpeersec_dgram, struct socket *sock, struct sk_buff *skb,
	u32 *secid)
{
	return call_int_hook(socket_getpeersec_dgram, -ENOPROTOOPT, sock,
				skb, secid);
}
EXPORT_SYMBOL(security_socket_getpeersec_dgram);

HOOK_HEAD(int, sk_alloc_security, struct sock *sk, int family, gfp_t priority);
int security_sk_alloc(struct sock *sk, int family, gfp_t priority)
{
	return call_int_hook(sk_alloc_security, 0, sk, family, priority);
}

HOOK_HEAD(void, sk_free_security, struct sock *sk);
void security_sk_free(struct sock *sk)
{
	call_void_hook(sk_free_security, sk);
}

HOOK_HEAD(void, sk_clone_security, const struct sock *sk, struct sock *newsk);
void security_sk_clone(const struct sock *sk, struct sock *newsk)
{
	call_void_hook(sk_clone_security, sk, newsk);
}
EXPORT_SYMBOL(security_sk_clone);

HOOK_HEAD(void, sk_getsecid, struct sock *sk, u32 *secid);
void security_sk_classify_flow(struct sock *sk, struct flowi *fl)
{
	call_void_hook(sk_getsecid, sk, &fl->flowi_secid);
}
EXPORT_SYMBOL(security_sk_classify_flow);

HOOK(void, req_classify_flow, const struct request_sock *req, struct flowi *fl)
{
	call_void_hook(req_classify_flow, req, fl);
}
EXPORT_SYMBOL(security_req_classify_flow);

HOOK(void, sock_graft, struct sock *sk, struct socket *parent)
{
	call_void_hook(sock_graft, sk, parent);
}
EXPORT_SYMBOL(security_sock_graft);

HOOK(int, inet_conn_request, struct sock *sk,
	struct sk_buff *skb, struct request_sock *req)
{
	return call_int_hook(inet_conn_request, 0, sk, skb, req);
}
EXPORT_SYMBOL(security_inet_conn_request);

HOOK(void, inet_csk_clone, struct sock *newsk, const struct request_sock *req)
{
	call_void_hook(inet_csk_clone, newsk, req);
}

HOOK(void, inet_conn_established, struct sock *sk, struct sk_buff *skb)
{
	call_void_hook(inet_conn_established, sk, skb);
}

HOOK(int, secmark_relabel_packet, u32 secid)
{
	return call_int_hook(secmark_relabel_packet, 0, secid);
}
EXPORT_SYMBOL(security_secmark_relabel_packet);

HOOK(void, secmark_refcount_inc, void)
{
	call_void_hook(secmark_refcount_inc);
}
EXPORT_SYMBOL(security_secmark_refcount_inc);

HOOK(void, secmark_refcount_dec, void)
{
	call_void_hook(secmark_refcount_dec);
}
EXPORT_SYMBOL(security_secmark_refcount_dec);


HOOK(int, tun_dev_create, void)
{
	return call_int_hook(tun_dev_create, 0);
}
EXPORT_SYMBOL(security_tun_dev_create);

HOOK(void, tun_dev_post_create, struct sock *sk)
{
	call_void_hook(tun_dev_post_create, sk);
}
EXPORT_SYMBOL(security_tun_dev_post_create);

HOOK(int, tun_dev_attach, struct sock *sk)
{
	return call_int_hook(tun_dev_attach, 0, sk);
}
EXPORT_SYMBOL(security_tun_dev_attach);

#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM

HOOK_HEAD(int, xfrm_policy_alloc_security, struct xfrm_sec_ctx **ctxp,
		struct xfrm_user_sec_ctx *sec_ctx);
int security_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp,
				struct xfrm_user_sec_ctx *sec_ctx)
{
	return call_int_hook(xfrm_policy_alloc_security, 0, ctxp, sec_ctx);
}
EXPORT_SYMBOL(security_xfrm_policy_alloc);

HOOK_HEAD(int, xfrm_policy_clone_security, struct xfrm_sec_ctx *old_ctx,
		struct xfrm_sec_ctx **new_ctxp);
int security_xfrm_policy_clone(struct xfrm_sec_ctx *old_ctx,
				struct xfrm_sec_ctx **new_ctxp)
{
	return call_int_hook(xfrm_policy_clone_security, 0, old_ctx, new_ctxp);
}

HOOK_HEAD(void, xfrm_policy_free_security, struct xfrm_sec_ctx *ctx);
void security_xfrm_policy_free(struct xfrm_sec_ctx *ctx)
{
	call_void_hook(xfrm_policy_free_security, ctx);
}
EXPORT_SYMBOL(security_xfrm_policy_free);

HOOK_HEAD(int, xfrm_policy_delete_security, struct xfrm_sec_ctx *ctx);
int security_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)
{
	return call_int_hook(xfrm_policy_delete_security, 0, ctx);
}

HOOK(int, xfrm_state_alloc, struct xfrm_state *x,
	struct xfrm_user_sec_ctx *sec_ctx)
{
	return call_int_hook(xfrm_state_alloc_security, 0, x, sec_ctx, 0);
}
EXPORT_SYMBOL(security_xfrm_state_alloc);

HOOK(int, xfrm_state_alloc_acquire, struct xfrm_state *x,
	struct xfrm_sec_ctx *polsec, u32 secid)
{
	if (!polsec)
		return 0;
	/*
	 * We want the context to be taken from secid which is usually
	 * from the sock.
	 */
	return call_int_hook(xfrm_state_alloc_security, 0, x, NULL, secid);
}

HOOK_HEAD(int, xfrm_state_delete_security, struct xfrm_state *x);
int security_xfrm_state_delete(struct xfrm_state *x)
{
	return call_int_hook(xfrm_state_delete_security, 0, x);
}
EXPORT_SYMBOL(security_xfrm_state_delete);

HOOK_HEAD(void, xfrm_state_free_security, struct xfrm_state *x);
void security_xfrm_state_free(struct xfrm_state *x)
{
	call_void_hook(xfrm_state_free_security, x);
}

HOOK(int, xfrm_policy_lookup, struct xfrm_sec_ctx *ctx, u32 fl_secid, u8 dir)
{
	return call_int_hook(xfrm_policy_lookup, 0, ctx, fl_secid, dir);
}

HOOK(int, xfrm_state_pol_flow_match, struct xfrm_state *x,
	struct xfrm_policy *xp, const struct flowi *fl)
{
	struct lsm_xfrm_state_pol_flow_match *hp;
	int rc = 1;

	/*
	 * Since this function is expected to return 0 or 1, the judgment
	 * becomes difficult if multiple LSMs supply this call. Fortunately,
	 * we can use the first LSM's judgment because currently only SELinux
	 * supplies this call.
	 *
	 * For speed optimization, we explicitly break the loop rather than
	 * using the macro
	 */
	list_for_each_entry(hp, &hooks_xfrm_state_pol_flow_match, list) {
		rc = hp->hook(x, xp, fl);
		break;
	}
	return rc;
}

HOOK_HEAD(int, xfrm_decode_session, struct sk_buff *skb, u32 *secid, int ckall);
int security_xfrm_decode_session(struct sk_buff *skb, u32 *secid)
{
	return call_int_hook(xfrm_decode_session, 0, skb, secid, 1);
}

void security_skb_classify_flow(struct sk_buff *skb, struct flowi *fl)
{
	int rc;

	rc = call_int_hook(xfrm_decode_session, 0, skb, &fl->flowi_secid, 0);

	BUG_ON(rc);
}
EXPORT_SYMBOL(security_skb_classify_flow);

#endif	/* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_KEYS

HOOK(int, key_alloc, struct key *key, const struct cred *cred,
	unsigned long flags)
{
	return call_int_hook(key_alloc, 0, key, cred, flags);
}

HOOK(void, key_free, struct key *key)
{
	call_void_hook(key_free, key);
}

HOOK(int, key_permission, key_ref_t key_ref,
			    const struct cred *cred, key_perm_t perm)
{
	return call_int_hook(key_permission, 0, key_ref, cred, perm);
}

HOOK(int, key_getsecurity, struct key *key, char **_buffer)
{
	*_buffer = NULL;
	return call_int_hook(key_getsecurity, 0, key, _buffer);
}

#endif	/* CONFIG_KEYS */

#ifdef CONFIG_AUDIT

HOOK(int, audit_rule_init, u32 field, u32 op, char *rulestr, void **lsmrule)
{
	return call_int_hook(audit_rule_init, 0, field, op, rulestr, lsmrule);
}

HOOK(int, audit_rule_known, struct audit_krule *krule)
{
	return call_int_hook(audit_rule_known, 0, krule);
}

HOOK(void, audit_rule_free, void *lsmrule)
{
	call_void_hook(audit_rule_free, lsmrule);
}

HOOK(int, audit_rule_match, u32 secid, u32 field, u32 op, void *lsmrule,
	struct audit_context *actx)
{
	return call_int_hook(audit_rule_match, 0, secid, field, op, lsmrule,
				actx);
}

#endif /* CONFIG_AUDIT */

static int __init add_hook_entry(struct list_head *hooklist, void *hook)
{
	struct security_hook_list *new;
	struct security_hook_list *shp;

	if (hook == NULL)
		return 0;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&new->list);
	new->vook = hook;

	//shp = list_last_entry(hooklist, struct security_hook_list, list);
	shp = list_entry(hooklist->prev, struct security_hook_list, list);
	list_add_rcu(&new->list, &shp->list);

	return 0;
}

#define add_hook(FUNC) add_hook_entry(&hooks_##FUNC, sop->FUNC)

static int __init security_enlist_ops(struct security_operations *sop)
{
	pr_info("Security operations for %s initialized\n", sop->name);

	/* Binder hooks */
	if (add_hook(binder_set_context_mgr))
		return -ENOMEM;
	if (add_hook(binder_transaction))
		return -ENOMEM;
	if (add_hook(binder_transfer_binder))
		return -ENOMEM;
	if (add_hook(binder_transfer_file))
		return -ENOMEM;

	if (add_hook(ptrace_access_check))
		return -ENOMEM;
	if (add_hook(ptrace_traceme))
		return -ENOMEM;
	if (add_hook(capget))
		return -ENOMEM;
	if (add_hook(capset))
		return -ENOMEM;
	if (add_hook(capable))
		return -ENOMEM;
	if (add_hook(quotactl))
		return -ENOMEM;
	if (add_hook(quota_on))
		return -ENOMEM;
	if (add_hook(syslog))
		return -ENOMEM;
	if (add_hook(settime))
		return -ENOMEM;
	if (add_hook(vm_enough_memory))
		return -ENOMEM;
	if (add_hook(bprm_set_creds))
		return -ENOMEM;
	if (add_hook(bprm_committing_creds))
		return -ENOMEM;
	if (add_hook(bprm_committed_creds))
		return -ENOMEM;
	if (add_hook(bprm_check_security))
		return -ENOMEM;
	if (add_hook(bprm_secureexec))
		return -ENOMEM;
	if (add_hook(sb_alloc_security))
		return -ENOMEM;
	if (add_hook(sb_free_security))
		return -ENOMEM;
	if (add_hook(sb_copy_data))
		return -ENOMEM;
	if (add_hook(sb_remount))
		return -ENOMEM;
	if (add_hook(sb_kern_mount))
		return -ENOMEM;
	if (add_hook(sb_show_options))
		return -ENOMEM;
	if (add_hook(sb_statfs))
		return -ENOMEM;
	if (add_hook(sb_mount))
		return -ENOMEM;
	if (add_hook(sb_umount))
		return -ENOMEM;
	if (add_hook(sb_pivotroot))
		return -ENOMEM;
	if (add_hook(sb_set_mnt_opts))
		return -ENOMEM;
	if (add_hook(sb_clone_mnt_opts))
		return -ENOMEM;
	if (add_hook(sb_parse_opts_str))
		return -ENOMEM;
	if (add_hook(inode_alloc_security))
		return -ENOMEM;
	if (add_hook(inode_free_security))
		return -ENOMEM;
	if (add_hook(inode_init_security))
		return -ENOMEM;
	if (add_hook(inode_create))
		return -ENOMEM;
	if (add_hook(inode_link))
		return -ENOMEM;
	if (add_hook(inode_unlink))
		return -ENOMEM;
	if (add_hook(inode_symlink))
		return -ENOMEM;
	if (add_hook(inode_mkdir))
		return -ENOMEM;
	if (add_hook(inode_rmdir))
		return -ENOMEM;
	if (add_hook(inode_mknod))
		return -ENOMEM;
	if (add_hook(inode_rename))
		return -ENOMEM;
	if (add_hook(inode_readlink))
		return -ENOMEM;
	if (add_hook(inode_follow_link))
		return -ENOMEM;
	if (add_hook(inode_permission))
		return -ENOMEM;
	if (add_hook(inode_setattr))
		return -ENOMEM;
	if (add_hook(inode_getattr))
		return -ENOMEM;
	if (add_hook(inode_setxattr))
		return -ENOMEM;
	if (add_hook(inode_post_setxattr))
		return -ENOMEM;
	if (add_hook(inode_getxattr))
		return -ENOMEM;
	if (add_hook(inode_listxattr))
		return -ENOMEM;
	if (add_hook(inode_removexattr))
		return -ENOMEM;
	if (add_hook(inode_need_killpriv))
		return -ENOMEM;
	if (add_hook(inode_killpriv))
		return -ENOMEM;
	if (add_hook(inode_getsecurity))
		return -ENOMEM;
	if (add_hook(inode_setsecurity))
		return -ENOMEM;
	if (add_hook(inode_listsecurity))
		return -ENOMEM;
	if (add_hook(inode_getsecid))
		return -ENOMEM;
#ifdef CONFIG_SECURITY_PATH
	if (add_hook(path_mknod))
		return -ENOMEM;
	if (add_hook(path_mkdir))
		return -ENOMEM;
	if (add_hook(path_rmdir))
		return -ENOMEM;
	if (add_hook(path_unlink))
		return -ENOMEM;
	if (add_hook(path_symlink))
		return -ENOMEM;
	if (add_hook(path_link))
		return -ENOMEM;
	if (add_hook(path_rename))
		return -ENOMEM;
	if (add_hook(path_truncate))
		return -ENOMEM;
	if (add_hook(path_chmod))
		return -ENOMEM;
	if (add_hook(path_chown))
		return -ENOMEM;
	if (add_hook(path_chroot))
		return -ENOMEM;
#endif
	if (add_hook(file_permission))
		return -ENOMEM;
	if (add_hook(file_alloc_security))
		return -ENOMEM;
	if (add_hook(file_free_security))
		return -ENOMEM;
	if (add_hook(file_ioctl))
		return -ENOMEM;
	if (add_hook(file_mmap))
		return -ENOMEM;
	if (add_hook(file_mprotect))
		return -ENOMEM;
	if (add_hook(file_lock))
		return -ENOMEM;
	if (add_hook(file_fcntl))
		return -ENOMEM;
	if (add_hook(file_set_fowner))
		return -ENOMEM;
	if (add_hook(file_send_sigiotask))
		return -ENOMEM;
	if (add_hook(file_receive))
		return -ENOMEM;
	if (add_hook(dentry_open))
		return -ENOMEM;
	if (add_hook(task_create))
		return -ENOMEM;
	if (add_hook(task_free))
		return -ENOMEM;
	if (add_hook(cred_alloc_blank))
		return -ENOMEM;
	if (add_hook(cred_free))
		return -ENOMEM;
	if (add_hook(cred_prepare))
		return -ENOMEM;
	if (add_hook(cred_transfer))
		return -ENOMEM;
	if (add_hook(kernel_act_as))
		return -ENOMEM;
	if (add_hook(kernel_create_files_as))
		return -ENOMEM;
	if (add_hook(kernel_module_request))
		return -ENOMEM;
	if (add_hook(task_fix_setuid))
		return -ENOMEM;
	if (add_hook(task_setpgid))
		return -ENOMEM;
	if (add_hook(task_getpgid))
		return -ENOMEM;
	if (add_hook(task_getsid))
		return -ENOMEM;
	if (add_hook(task_getsecid))
		return -ENOMEM;
	if (add_hook(task_setnice))
		return -ENOMEM;
	if (add_hook(task_setioprio))
		return -ENOMEM;
	if (add_hook(task_getioprio))
		return -ENOMEM;
	if (add_hook(task_setrlimit))
		return -ENOMEM;
	if (add_hook(task_setscheduler))
		return -ENOMEM;
	if (add_hook(task_getscheduler))
		return -ENOMEM;
	if (add_hook(task_movememory))
		return -ENOMEM;
	if (add_hook(task_wait))
		return -ENOMEM;
	if (add_hook(task_kill))
		return -ENOMEM;
	if (add_hook(task_prctl))
		return -ENOMEM;
	if (add_hook(task_to_inode))
		return -ENOMEM;
	if (add_hook(ipc_permission))
		return -ENOMEM;
	if (add_hook(ipc_getsecid))
		return -ENOMEM;
	if (add_hook(msg_msg_alloc_security))
		return -ENOMEM;
	if (add_hook(msg_msg_free_security))
		return -ENOMEM;
	if (add_hook(msg_queue_alloc_security))
		return -ENOMEM;
	if (add_hook(msg_queue_free_security))
		return -ENOMEM;
	if (add_hook(msg_queue_associate))
		return -ENOMEM;
	if (add_hook(msg_queue_msgctl))
		return -ENOMEM;
	if (add_hook(msg_queue_msgsnd))
		return -ENOMEM;
	if (add_hook(msg_queue_msgrcv))
		return -ENOMEM;
	if (add_hook(shm_alloc_security))
		return -ENOMEM;
	if (add_hook(shm_free_security))
		return -ENOMEM;
	if (add_hook(shm_associate))
		return -ENOMEM;
	if (add_hook(shm_shmctl))
		return -ENOMEM;
	if (add_hook(shm_shmat))
		return -ENOMEM;
	if (add_hook(sem_alloc_security))
		return -ENOMEM;
	if (add_hook(sem_free_security))
		return -ENOMEM;
	if (add_hook(sem_associate))
		return -ENOMEM;
	if (add_hook(sem_semctl))
		return -ENOMEM;
	if (add_hook(sem_semop))
		return -ENOMEM;
	if (add_hook(netlink_send))
		return -ENOMEM;
	if (add_hook(d_instantiate))
		return -ENOMEM;
	if (add_hook(getprocattr))
		return -ENOMEM;
	if (add_hook(setprocattr))
		return -ENOMEM;
	if (add_hook(secid_to_secctx))
		return -ENOMEM;
	if (add_hook(secctx_to_secid))
		return -ENOMEM;
	if (add_hook(release_secctx))
		return -ENOMEM;
	if (add_hook(inode_notifysecctx))
		return -ENOMEM;
	if (add_hook(inode_setsecctx))
		return -ENOMEM;
	if (add_hook(inode_getsecctx))
		return -ENOMEM;
#ifdef CONFIG_SECURITY_NETWORK
	if (add_hook(unix_stream_connect))
		return -ENOMEM;
	if (add_hook(unix_may_send))
		return -ENOMEM;
	if (add_hook(socket_create))
		return -ENOMEM;
	if (add_hook(socket_post_create))
		return -ENOMEM;
	if (add_hook(socket_bind))
		return -ENOMEM;
	if (add_hook(socket_connect))
		return -ENOMEM;
	if (add_hook(socket_listen))
		return -ENOMEM;
	if (add_hook(socket_accept))
		return -ENOMEM;
	if (add_hook(socket_sendmsg))
		return -ENOMEM;
	if (add_hook(socket_recvmsg))
		return -ENOMEM;
	if (add_hook(socket_getsockname))
		return -ENOMEM;
	if (add_hook(socket_getpeername))
		return -ENOMEM;
	if (add_hook(socket_setsockopt))
		return -ENOMEM;
	if (add_hook(socket_getsockopt))
		return -ENOMEM;
	if (add_hook(socket_shutdown))
		return -ENOMEM;
	if (add_hook(socket_sock_rcv_skb))
		return -ENOMEM;
	if (add_hook(socket_getpeersec_stream))
		return -ENOMEM;
	if (add_hook(socket_getpeersec_dgram))
		return -ENOMEM;
	if (add_hook(sk_alloc_security))
		return -ENOMEM;
	if (add_hook(sk_free_security))
		return -ENOMEM;
	if (add_hook(sk_clone_security))
		return -ENOMEM;
	if (add_hook(sk_getsecid))
		return -ENOMEM;
	if (add_hook(sock_graft))
		return -ENOMEM;
	if (add_hook(inet_conn_request))
		return -ENOMEM;
	if (add_hook(inet_csk_clone))
		return -ENOMEM;
	if (add_hook(inet_conn_established))
		return -ENOMEM;
	if (add_hook(secmark_relabel_packet))
		return -ENOMEM;
	if (add_hook(secmark_refcount_inc))
		return -ENOMEM;
	if (add_hook(secmark_refcount_dec))
		return -ENOMEM;
	if (add_hook(req_classify_flow))
		return -ENOMEM;
	if (add_hook(tun_dev_create))
		return -ENOMEM;
	if (add_hook(tun_dev_post_create))
		return -ENOMEM;
	if (add_hook(tun_dev_attach))
		return -ENOMEM;
#endif	/* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	if (add_hook(xfrm_policy_alloc_security))
		return -ENOMEM;
	if (add_hook(xfrm_policy_clone_security))
		return -ENOMEM;
	if (add_hook(xfrm_policy_free_security))
		return -ENOMEM;
	if (add_hook(xfrm_policy_delete_security))
		return -ENOMEM;
	if (add_hook(xfrm_state_alloc))
		return -ENOMEM;
	if (add_hook(xfrm_state_alloc_acquire))
		return -ENOMEM;
	if (add_hook(xfrm_state_free_security))
		return -ENOMEM;
	if (add_hook(xfrm_state_delete_security))
		return -ENOMEM;
	if (add_hook(xfrm_policy_lookup))
		return -ENOMEM;
	if (add_hook(xfrm_state_pol_flow_match))
		return -ENOMEM;
	if (add_hook(xfrm_decode_session))
		return -ENOMEM;
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
	if (add_hook(key_alloc))
		return -ENOMEM;
	if (add_hook(key_free))
		return -ENOMEM;
	if (add_hook(key_permission))
		return -ENOMEM;
	if (add_hook(key_getsecurity))
		return -ENOMEM;
#endif	/* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
	if (add_hook(audit_rule_init))
		return -ENOMEM;
	if (add_hook(audit_rule_known))
		return -ENOMEM;
	if (add_hook(audit_rule_match))
		return -ENOMEM;
	if (add_hook(audit_rule_free))
		return -ENOMEM;
#endif
	return 0;
}

#ifdef CONFIG_SECURITY_SELINUX_DISABLE
static void clear_hook_entry(struct list_head *head, void *hook)
{
	struct security_hook_list *shp;

	if (hook) {
		list_for_each_entry(shp, head, list)
			if (shp->vook == hook) {
				list_del_rcu(&shp->list);
				return;
			}
	}
}

#define clear_hook(FUNC) clear_hook_entry(&hooks_##FUNC, sop->FUNC)

void security_module_disable(struct security_operations *sop)
{
	pr_info("Security operations for %s disabled.\n", sop->name);
	/* Binder hooks */
	clear_hook(binder_set_context_mgr);
	clear_hook(binder_transaction);
	clear_hook(binder_transfer_binder);
	clear_hook(binder_transfer_file);

	clear_hook(ptrace_access_check);
	clear_hook(ptrace_traceme);
	clear_hook(capget);
	clear_hook(capset);
	clear_hook(capable);
	clear_hook(quotactl);
	clear_hook(quota_on);
	clear_hook(syslog);
	clear_hook(settime);
	clear_hook(vm_enough_memory);
	clear_hook(bprm_set_creds);
	clear_hook(bprm_committing_creds);
	clear_hook(bprm_committed_creds);
	clear_hook(bprm_check_security);
	clear_hook(bprm_secureexec);
	clear_hook(sb_alloc_security);
	clear_hook(sb_free_security);
	clear_hook(sb_copy_data);
	clear_hook(sb_remount);
	clear_hook(sb_kern_mount);
	clear_hook(sb_show_options);
	clear_hook(sb_statfs);
	clear_hook(sb_mount);
	clear_hook(sb_umount);
	clear_hook(sb_pivotroot);
	clear_hook(sb_set_mnt_opts);
	clear_hook(sb_clone_mnt_opts);
	clear_hook(sb_parse_opts_str);
	clear_hook(inode_alloc_security);
	clear_hook(inode_free_security);
	clear_hook(inode_init_security);
	clear_hook(inode_create);
	clear_hook(inode_link);
	clear_hook(inode_unlink);
	clear_hook(inode_symlink);
	clear_hook(inode_mkdir);
	clear_hook(inode_rmdir);
	clear_hook(inode_mknod);
	clear_hook(inode_rename);
	clear_hook(inode_readlink);
	clear_hook(inode_follow_link);
	clear_hook(inode_permission);
	clear_hook(inode_setattr);
	clear_hook(inode_getattr);
	clear_hook(inode_setxattr);
	clear_hook(inode_post_setxattr);
	clear_hook(inode_getxattr);
	clear_hook(inode_listxattr);
	clear_hook(inode_removexattr);
	clear_hook(inode_need_killpriv);
	clear_hook(inode_killpriv);
	clear_hook(inode_getsecurity);
	clear_hook(inode_setsecurity);
	clear_hook(inode_listsecurity);
	clear_hook(inode_getsecid);
#ifdef CONFIG_SECURITY_PATH
	clear_hook(path_mknod);
	clear_hook(path_mkdir);
	clear_hook(path_rmdir);
	clear_hook(path_unlink);
	clear_hook(path_symlink);
	clear_hook(path_link);
	clear_hook(path_rename);
	clear_hook(path_truncate);
	clear_hook(path_chmod);
	clear_hook(path_chown);
	clear_hook(path_chroot);
#endif
	clear_hook(file_permission);
	clear_hook(file_alloc_security);
	clear_hook(file_free_security);
	clear_hook(file_ioctl);
	clear_hook(file_mmap);
	clear_hook(file_mprotect);
	clear_hook(file_lock);
	clear_hook(file_fcntl);
	clear_hook(file_set_fowner);
	clear_hook(file_send_sigiotask);
	clear_hook(file_receive);
	clear_hook(dentry_open);
	clear_hook(task_create);
	clear_hook(task_free);
	clear_hook(cred_alloc_blank);
	clear_hook(cred_free);
	clear_hook(cred_prepare);
	clear_hook(cred_transfer);
	clear_hook(kernel_act_as);
	clear_hook(kernel_create_files_as);
	clear_hook(kernel_module_request);
	clear_hook(task_fix_setuid);
	clear_hook(task_setpgid);
	clear_hook(task_getpgid);
	clear_hook(task_getsid);
	clear_hook(task_getsecid);
	clear_hook(task_setnice);
	clear_hook(task_setioprio);
	clear_hook(task_getioprio);
	clear_hook(task_setrlimit);
	clear_hook(task_setscheduler);
	clear_hook(task_getscheduler);
	clear_hook(task_movememory);
	clear_hook(task_wait);
	clear_hook(task_kill);
	clear_hook(task_prctl);
	clear_hook(task_to_inode);
	clear_hook(ipc_permission);
	clear_hook(ipc_getsecid);
	clear_hook(msg_msg_alloc_security);
	clear_hook(msg_msg_free_security);
	clear_hook(msg_queue_alloc_security);
	clear_hook(msg_queue_free_security);
	clear_hook(msg_queue_associate);
	clear_hook(msg_queue_msgctl);
	clear_hook(msg_queue_msgsnd);
	clear_hook(msg_queue_msgrcv);
	clear_hook(shm_alloc_security);
	clear_hook(shm_free_security);
	clear_hook(shm_associate);
	clear_hook(shm_shmctl);
	clear_hook(shm_shmat);
	clear_hook(sem_alloc_security);
	clear_hook(sem_free_security);
	clear_hook(sem_associate);
	clear_hook(sem_semctl);
	clear_hook(sem_semop);
	clear_hook(netlink_send);
	clear_hook(d_instantiate);
	clear_hook(getprocattr);
	clear_hook(setprocattr);
	clear_hook(secid_to_secctx);
	clear_hook(secctx_to_secid);
	clear_hook(release_secctx);
	clear_hook(inode_notifysecctx);
	clear_hook(inode_setsecctx);
	clear_hook(inode_getsecctx);
#ifdef CONFIG_SECURITY_NETWORK
	clear_hook(unix_stream_connect);
	clear_hook(unix_may_send);
	clear_hook(socket_create);
	clear_hook(socket_post_create);
	clear_hook(socket_bind);
	clear_hook(socket_connect);
	clear_hook(socket_listen);
	clear_hook(socket_accept);
	clear_hook(socket_sendmsg);
	clear_hook(socket_recvmsg);
	clear_hook(socket_getsockname);
	clear_hook(socket_getpeername);
	clear_hook(socket_setsockopt);
	clear_hook(socket_getsockopt);
	clear_hook(socket_shutdown);
	clear_hook(socket_sock_rcv_skb);
	clear_hook(socket_getpeersec_stream);
	clear_hook(socket_getpeersec_dgram);
	clear_hook(sk_alloc_security);
	clear_hook(sk_free_security);
	clear_hook(sk_clone_security);
	clear_hook(sk_getsecid);
	clear_hook(sock_graft);
	clear_hook(inet_conn_request);
	clear_hook(inet_csk_clone);
	clear_hook(inet_conn_established);
	clear_hook(secmark_relabel_packet);
	clear_hook(secmark_refcount_inc);
	clear_hook(secmark_refcount_dec);
	clear_hook(req_classify_flow);
	clear_hook(tun_dev_create);
	clear_hook(tun_dev_post_create);
	clear_hook(tun_dev_attach);
#endif	/* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	clear_hook(xfrm_policy_alloc_security);
	clear_hook(xfrm_policy_clone_security);
	clear_hook(xfrm_policy_free_security);
	clear_hook(xfrm_policy_delete_security);
	clear_hook(xfrm_state_alloc);
	clear_hook(xfrm_state_alloc_acquire);
	clear_hook(xfrm_state_free_security);
	clear_hook(xfrm_state_delete_security);
	clear_hook(xfrm_policy_lookup);
	clear_hook(xfrm_state_pol_flow_match);
	clear_hook(xfrm_decode_session);
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
	clear_hook(key_alloc);
	clear_hook(key_free);
	clear_hook(key_permission);
	clear_hook(key_getsecurity);
#endif	/* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
	clear_hook(audit_rule_init);
	clear_hook(audit_rule_known);
	clear_hook(audit_rule_match);
	clear_hook(audit_rule_free);
#endif
}
#endif /* CONFIG_SECURITY_SELINUX_DISABLE */
