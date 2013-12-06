/*
 * Copyright (C) 2012 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM binder

#if !defined(_BINDER_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _BINDER_TRACE_H

#include <linux/tracepoint.h>

struct binder_buffer;
struct binder_node;
struct binder_proc;
struct binder_ref;
struct binder_thread;
struct binder_transaction;

TRACE_EVENT(binder_ioctl,
	TP_PROTO(struct binder_proc *proc, unsigned int cmd, unsigned long arg),
	TP_ARGS(proc, cmd, arg),

	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(unsigned int, cmd)
		__field(unsigned long, arg)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->cmd = cmd;
		__entry->arg = arg;
	),
	    TP_printk("dev_ns=%s cmd=0x%x arg=0x%lx",
		      __entry->dev_ns, __entry->cmd, __entry->arg)
);

DECLARE_EVENT_CLASS(binder_lock_class,
	TP_PROTO(struct binder_proc *proc, const char *tag),
	TP_ARGS(proc, tag),
	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(const char *, tag)
	),
	TP_fast_assign(
		__entry->dev_ns = proc ?
			proc->binder_ns->dev_ns_info.dev_ns->tag : NULL;
		__entry->tag = tag;
	),
	TP_printk("dev_ns=%s tag=%s",
		  __entry->dev_ns ? __entry->dev_ns : "_global_", __entry->tag)
);

#define DEFINE_BINDER_LOCK_EVENT(name)	\
DEFINE_EVENT(binder_lock_class, name,	\
	TP_PROTO(struct binder_proc *proc, const char *func),	\
	TP_ARGS(proc, func))

DEFINE_BINDER_LOCK_EVENT(binder_lock);
DEFINE_BINDER_LOCK_EVENT(binder_locked);
DEFINE_BINDER_LOCK_EVENT(binder_unlock);

DECLARE_EVENT_CLASS(binder_function_return_class,
	TP_PROTO(struct binder_proc *proc, int ret),
	TP_ARGS(proc, ret),
	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(int, ret)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->ret = ret;
	),
	TP_printk("dev_ns=%s ret=%d", __entry->dev_ns, __entry->ret)
);

#define DEFINE_BINDER_FUNCTION_RETURN_EVENT(name)	\
DEFINE_EVENT(binder_function_return_class, name,	\
	TP_PROTO(struct binder_proc *proc, int ret), \
	TP_ARGS(proc, ret))

DEFINE_BINDER_FUNCTION_RETURN_EVENT(binder_ioctl_done);
DEFINE_BINDER_FUNCTION_RETURN_EVENT(binder_write_done);
DEFINE_BINDER_FUNCTION_RETURN_EVENT(binder_read_done);

TRACE_EVENT(binder_wait_for_work,
	TP_PROTO(struct binder_proc *proc,
		 bool proc_work, bool transaction_stack, bool thread_todo),
	TP_ARGS(proc, proc_work, transaction_stack, thread_todo),

	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(bool, proc_work)
		__field(bool, transaction_stack)
		__field(bool, thread_todo)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->proc_work = proc_work;
		__entry->transaction_stack = transaction_stack;
		__entry->thread_todo = thread_todo;
	),
	TP_printk("dev_ns=%s proc_work=%d transaction_stack=%d thread_todo=%d",
		  __entry->dev_ns, __entry->proc_work, __entry->transaction_stack,
		  __entry->thread_todo)
);

TRACE_EVENT(binder_transaction,
	TP_PROTO(struct binder_proc *proc,
		 bool reply, struct binder_transaction *t,
		 struct binder_node *target_node),
	TP_ARGS(proc, reply, t, target_node),
	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(int, debug_id)
		__field(int, target_node)
		__field(int, to_proc)
		__field(int, to_thread)
		__field(int, reply)
		__field(unsigned int, code)
		__field(unsigned int, flags)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->debug_id = t->debug_id;
		__entry->target_node = target_node ? target_node->debug_id : 0;
		__entry->to_proc = t->to_proc->pid;
		__entry->to_thread = t->to_thread ? t->to_thread->pid : 0;
		__entry->reply = reply;
		__entry->code = t->code;
		__entry->flags = t->flags;
	),
	TP_printk("dev_ns=%s transaction=%d dest_node=%d dest_proc=%d dest_thread=%d reply=%d flags=0x%x code=0x%x",
		  __entry->dev_ns, __entry->debug_id, __entry->target_node,
		  __entry->to_proc, __entry->to_thread,
		  __entry->reply, __entry->flags, __entry->code)
);

TRACE_EVENT(binder_transaction_received,
	TP_PROTO(struct binder_proc *proc, struct binder_transaction *t),
	TP_ARGS(proc, t),

	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(int, debug_id)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->debug_id = t->debug_id;
	),
	    TP_printk("dev_ns=%s transaction=%d", __entry->dev_ns, __entry->debug_id)
);

TRACE_EVENT(binder_transaction_node_to_ref,
	TP_PROTO(struct binder_proc *proc, 
		 struct binder_transaction *t, struct binder_node *node,
		 struct binder_ref *ref),
	TP_ARGS(proc, t, node, ref),

	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(int, debug_id)
		__field(int, node_debug_id)
		__field(void __user *, node_ptr)
		__field(int, ref_debug_id)
		__field(uint32_t, ref_desc)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->debug_id = t->debug_id;
		__entry->node_debug_id = node->debug_id;
		__entry->node_ptr = node->ptr;
		__entry->ref_debug_id = ref->debug_id;
		__entry->ref_desc = ref->desc;
	),
	TP_printk("dev_ns=%s transaction=%d node=%d src_ptr=0x%p ==> dest_ref=%d dest_desc=%d",
		  __entry->dev_ns,
		  __entry->debug_id, __entry->node_debug_id, __entry->node_ptr,
		  __entry->ref_debug_id, __entry->ref_desc)
);

TRACE_EVENT(binder_transaction_ref_to_node,
	TP_PROTO(struct binder_proc *proc,
		 struct binder_transaction *t, struct binder_ref *ref),
	TP_ARGS(proc, t, ref),

	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(int, debug_id)
		__field(int, ref_debug_id)
		__field(uint32_t, ref_desc)
		__field(int, node_debug_id)
		__field(void __user *, node_ptr)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->debug_id = t->debug_id;
		__entry->ref_debug_id = ref->debug_id;
		__entry->ref_desc = ref->desc;
		__entry->node_debug_id = ref->node->debug_id;
		__entry->node_ptr = ref->node->ptr;
	),
	TP_printk("dev_ns=%s transaction=%d node=%d src_ref=%d src_desc=%d ==> dest_ptr=0x%p",
		  __entry->dev_ns, __entry->debug_id, __entry->node_debug_id,
		  __entry->ref_debug_id, __entry->ref_desc, __entry->node_ptr)
);

TRACE_EVENT(binder_transaction_ref_to_ref,
	TP_PROTO(struct binder_proc *proc,
		 struct binder_transaction *t, struct binder_ref *src_ref,
		 struct binder_ref *dest_ref),
	TP_ARGS(proc, t, src_ref, dest_ref),

	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(int, debug_id)
		__field(int, node_debug_id)
		__field(int, src_ref_debug_id)
		__field(uint32_t, src_ref_desc)
		__field(int, dest_ref_debug_id)
		__field(uint32_t, dest_ref_desc)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->debug_id = t->debug_id;
		__entry->node_debug_id = src_ref->node->debug_id;
		__entry->src_ref_debug_id = src_ref->debug_id;
		__entry->src_ref_desc = src_ref->desc;
		__entry->dest_ref_debug_id = dest_ref->debug_id;
		__entry->dest_ref_desc = dest_ref->desc;
	),
	TP_printk("dev_ns=%s transaction=%d node=%d src_ref=%d src_desc=%d ==> dest_ref=%d dest_desc=%d",
		  __entry->dev_ns, __entry->debug_id, __entry->node_debug_id,
		  __entry->src_ref_debug_id, __entry->src_ref_desc,
		  __entry->dest_ref_debug_id, __entry->dest_ref_desc)
);

TRACE_EVENT(binder_transaction_fd,
	TP_PROTO(struct binder_proc *proc,
		 struct binder_transaction *t, int src_fd, int dest_fd),
	TP_ARGS(proc, t, src_fd, dest_fd),

	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(int, debug_id)
		__field(int, src_fd)
		__field(int, dest_fd)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->debug_id = t->debug_id;
		__entry->src_fd = src_fd;
		__entry->dest_fd = dest_fd;
	),
	TP_printk("dev_ns=%s transaction=%d src_fd=%d ==> dest_fd=%d",
		  __entry->dev_ns,
		  __entry->debug_id, __entry->src_fd, __entry->dest_fd)
);

DECLARE_EVENT_CLASS(binder_buffer_class,
	TP_PROTO(struct binder_proc *proc, struct binder_buffer *buf),
	TP_ARGS(proc, buf),
	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(int, debug_id)
		__field(size_t, data_size)
		__field(size_t, offsets_size)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->debug_id = buf->debug_id;
		__entry->data_size = buf->data_size;
		__entry->offsets_size = buf->offsets_size;
	),
	TP_printk("dev_ns=%s transaction=%d data_size=%zd offsets_size=%zd",
		  __entry->dev_ns,
		  __entry->debug_id, __entry->data_size, __entry->offsets_size)
);

DEFINE_EVENT(binder_buffer_class, binder_transaction_alloc_buf,
	TP_PROTO(struct binder_proc *proc, struct binder_buffer *buffer),
	TP_ARGS(proc, buffer));

DEFINE_EVENT(binder_buffer_class, binder_transaction_buffer_release,
	TP_PROTO(struct binder_proc *proc, struct binder_buffer *buffer),
	TP_ARGS(proc, buffer));

DEFINE_EVENT(binder_buffer_class, binder_transaction_failed_buffer_release,
	TP_PROTO(struct binder_proc *proc, struct binder_buffer *buffer),
	TP_ARGS(proc, buffer));

TRACE_EVENT(binder_update_page_range,
	TP_PROTO(struct binder_proc *proc, bool allocate,
		 void *start, void *end),
	TP_ARGS(proc, allocate, start, end),
	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(int, proc)
		__field(bool, allocate)
		__field(size_t, offset)
		__field(size_t, size)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->proc = proc->pid;
		__entry->allocate = allocate;
		__entry->offset = start - proc->buffer;
		__entry->size = end - start;
	),
	TP_printk("dev_ns=%s proc=%d allocate=%d offset=%zu size=%zu",
		  __entry->dev_ns, __entry->proc, __entry->allocate,
		  __entry->offset, __entry->size)
);

TRACE_EVENT(binder_command,
	TP_PROTO(struct binder_proc *proc, uint32_t cmd),
	TP_ARGS(proc, cmd),
	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(uint32_t, cmd)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->cmd = cmd;
	),
	TP_printk("dev_ns=%s cmd=0x%x %s",
		  __entry->dev_ns, __entry->cmd,
		  _IOC_NR(__entry->cmd) < ARRAY_SIZE(binder_command_strings) ?
			  binder_command_strings[_IOC_NR(__entry->cmd)] :
			  "unknown")
);

TRACE_EVENT(binder_return,
	TP_PROTO(struct binder_proc *proc, uint32_t cmd),
	TP_ARGS(proc, cmd),
	TP_STRUCT__entry(
		__field(const char*, dev_ns)
		__field(uint32_t, cmd)
	),
	TP_fast_assign(
		__entry->dev_ns = proc->binder_ns->dev_ns_info.dev_ns->tag;
		__entry->cmd = cmd;
	),
	TP_printk("dev_ns=%s cmd=0x%x %s",
		  __entry->dev_ns, __entry->cmd,
		  _IOC_NR(__entry->cmd) < ARRAY_SIZE(binder_return_strings) ?
			  binder_return_strings[_IOC_NR(__entry->cmd)] :
			  "unknown")
);

#endif /* _BINDER_TRACE_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE binder_trace_dev_ns
#include <trace/define_trace.h>
