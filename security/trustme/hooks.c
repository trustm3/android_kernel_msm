#include <linux/lsm_hooks.h>

static int trustme_binder_set_context_mgr(struct task_struct *mgr)
{
	printk(KERN_INFO "trustme-lsm: binder_set_context_mgr called");
	return 0;
}

static int trustme_capable(const struct cred *cred, struct user_namespace *ns,
			int cap, int audit)
{
	//printk(KERN_INFO "trustme-lsm: trustme_capable hook called");
	return 0;
}

static struct security_hook_list trustme_hooks[] = {
	LSM_HOOK_INIT(binder_set_context_mgr, trustme_binder_set_context_mgr),
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
