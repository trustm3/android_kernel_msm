/*
 * Event char devices, giving access to raw input device events.
 *
 * Copyright (c) 1999-2002 Vojtech Pavlik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifdef CONFIG_INPUT_DEV_NS
#define DEBUG
#define DEV_NS_EVDEV_DEBUG

#ifdef DEV_NS_EVDEV_DEBUG
#define pr_fmt(fmt) \
	"[%d] devns:evdev [%s:%d]: " fmt, \
	current->pid, __func__, __LINE__
#else
#define pr_fmt(fmt) \
	"[%d] devns:evdev: " fmt, current->pid
#endif
#endif /* CONFIG_INPUT_DEV_NS */

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#define EVDEV_MINOR_BASE	64
#define EVDEV_MINORS		32
#define EVDEV_MIN_BUFFER_SIZE	64U
#define EVDEV_BUF_PACKETS	8

#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/input/mt.h>
#include <linux/major.h>
#include <linux/device.h>
#include <linux/wakelock.h>
#ifdef CONFIG_INPUT_DEV_NS
#include <linux/dev_namespace.h>
#endif

#include "input-compat.h"

struct evdev {
	int open;
	int minor;
	struct input_handle handle;
	wait_queue_head_t wait;
	struct evdev_client __rcu *grab;
	struct list_head client_list;
	spinlock_t client_lock; /* protects client_list */
	struct mutex mutex;
	struct device dev;
	bool exist;
	int hw_ts_sec;
	int hw_ts_nsec;
#ifdef CONFIG_INPUT_DEV_NS
	int pb_pressed_short;
	struct timer_list pb_timer;
#endif
};

#ifdef CONFIG_INPUT_DEV_NS
struct evdev_dev_ns;
#endif

struct evdev_client {
	unsigned int head;
	unsigned int tail;
	unsigned int packet_head; /* [future] position of the first element of next packet */
	spinlock_t buffer_lock; /* protects access to buffer, head and tail */
	struct wake_lock wake_lock;
	bool use_wake_lock;
	char name[44];
#ifdef CONFIG_INPUT_DEV_NS
	struct evdev_dev_ns *evdev_ns;
	struct list_head list;
	bool grab;
#endif
	struct fasync_struct *fasync;
	struct evdev *evdev;
	struct list_head node;
	int clkid;
	unsigned int bufsize;
	struct input_event buffer[];
};

static struct evdev *evdev_table[EVDEV_MINORS];
static DEFINE_MUTEX(evdev_table_mutex);

/*
 * Multiplex inputs events between device namespaces (evdev, mousedev).
 *
 * Keep track of the device namespace of clients, and deliver input events
 * only to those clients that belong to an active (foreground) namespace.
 * Thus, listeners in background namespaces are oblivious to such input.
 *
 * With evdev, input grab depends on the device namespace context. Only
 * clients in an active namespace can really grab an input, and from an active
 * namespace, grab operates as usual. From a background namespace, input grab
 * is done virtually: if no other clients in same namespace have the grab, the
 * operation succeeds and the client is marked as having the grab, but no
 * action is taken. When another namepace becomes active, grabs are swapped:
 * current real grabs are undone and instead become virtual, and virtual grabs
 * are forced and become real.
 */

#ifdef CONFIG_INPUT_DEV_NS
struct evdev_dev_ns {
	struct mutex mutex;
	struct list_head clients;
	struct dev_ns_info dev_ns_info;
};

/* evdev_ns_id, get_evdev_ns(), get_evdev_ns_cur(), put_evdev_ns() */
DEFINE_DEV_NS_INFO(evdev)

/* indicate whether an evdev client is in the foreground */
static bool evdev_client_is_active(struct evdev_client *client)
{
	return is_active_dev_ns(client->evdev_ns->dev_ns_info.dev_ns);
}

static struct notifier_block evdev_ns_switch_notifier;
static int evdev_grab(struct evdev *evdev, struct evdev_client *client);
static int evdev_ungrab(struct evdev *evdev, struct evdev_client *client);

/* evdev_ns helpers */
static struct dev_ns_info *evdev_devns_create(struct dev_namespace *dev_ns)
{
	struct evdev_dev_ns *evdev_ns;
	struct dev_ns_info *dev_ns_info;

	evdev_ns = kzalloc(sizeof(*evdev_ns), GFP_KERNEL);
	if (!evdev_ns)
		return ERR_PTR(-ENOMEM);

	mutex_init(&evdev_ns->mutex);
	INIT_LIST_HEAD(&evdev_ns->clients);

	pr_info("new evdev_dev_ns %p (d %p)\n", evdev_ns, dev_ns);

	dev_ns_info = &evdev_ns->dev_ns_info;

	dev_ns_info->nb = evdev_ns_switch_notifier;
	dev_ns_register_notify(dev_ns, &dev_ns_info->nb);

	return &evdev_ns->dev_ns_info;

}

static void evdev_devns_release(struct dev_ns_info *dev_ns_info)
{
	struct evdev_dev_ns *evdev_ns;

	evdev_ns = container_of(dev_ns_info, struct evdev_dev_ns, dev_ns_info);

	pr_info("del evdev_dev_ns %p (d %p)\n", evdev_ns, dev_ns_info->dev_ns);
	dev_ns_unregister_notify(dev_ns_info->dev_ns, &dev_ns_info->nb);

	kfree(evdev_ns);
}

static struct dev_ns_ops evdev_ns_ops = {
	.create = evdev_devns_create,
	.release = evdev_devns_release,
};

static int evdev_ns_track_client(struct evdev_client *client)
{
	struct evdev_dev_ns *evdev_ns;

	evdev_ns = get_evdev_ns_cur();
	if (!evdev_ns)
		return -ENOMEM;

	pr_info("track new client 0x%p in evdev_ns 0x%p (dev_ns 0x%p)\n",
		client, evdev_ns, evdev_ns->dev_ns_info.dev_ns);

	client->evdev_ns = evdev_ns;
	client->grab = false;

	mutex_lock(&evdev_ns->mutex);
	list_add(&client->list, &evdev_ns->clients);
	mutex_unlock(&evdev_ns->mutex);

	return 0;
}

static void evdev_ns_untrack_client(struct evdev_client *client)
{
	struct evdev_dev_ns *evdev_ns;

	evdev_ns = client->evdev_ns;

	pr_info("untrack client 0x%p in evdev_ns 0x%p (dev_ns 0x%p)\n",
		client, evdev_ns, evdev_ns->dev_ns_info.dev_ns);

	mutex_lock(&evdev_ns->mutex);
	list_del(&client->list);
	mutex_unlock(&evdev_ns->mutex);

	put_evdev_ns(evdev_ns);
}

/* dev_ns and resepctive fb_dev_ns protected by caller */
static int evdev_ns_switch_callback(struct notifier_block *self,
				    unsigned long action, void *data)
{
	struct dev_namespace *dev_ns = data;
	struct evdev_dev_ns *evdev_ns;
	struct evdev_client *client;

	evdev_ns = find_evdev_ns(dev_ns);
	WARN(evdev_ns == NULL, "devns 0x%p: no matching evdev_ns\n", dev_ns);

	mutex_lock(&evdev_ns->mutex);
	switch (action) {
	case DEV_NS_EVENT_ACTIVATE:
		list_for_each_entry(client, &evdev_ns->clients, list)
		{
			mutex_lock(&client->evdev->mutex);
			if (client->grab)
				evdev_grab(client->evdev, client);
			mutex_unlock(&client->evdev->mutex);
		}
		break;
	case DEV_NS_EVENT_DEACTIVATE:
		list_for_each_entry(client, &evdev_ns->clients, list)
		{
			mutex_lock(&client->evdev->mutex);
			if (client->evdev->grab == client)
				evdev_ungrab(client->evdev, client);
			mutex_unlock(&client->evdev->mutex);
		}
		break;
	}
	mutex_unlock(&evdev_ns->mutex);
	return 0;
}

static struct notifier_block evdev_ns_switch_notifier = {
	.notifier_call = evdev_ns_switch_callback,
};
#endif /* CONFIG_INPUT_DEV_NS */

static void evdev_pass_event(struct evdev_client *client,
			     struct input_event *event,
			     ktime_t mono, ktime_t real)
{
	event->time = ktime_to_timeval(client->clkid == CLOCK_MONOTONIC ?
					mono : real);

	/* Interrupts are disabled, just acquire the lock. */
	spin_lock(&client->buffer_lock);

	client->buffer[client->head++] = *event;
	client->head &= client->bufsize - 1;

	if (unlikely(client->head == client->tail)) {
		/*
		 * This effectively "drops" all unconsumed events, leaving
		 * EV_SYN/SYN_DROPPED plus the newest event in the queue.
		 */
		client->tail = (client->head - 2) & (client->bufsize - 1);

		client->buffer[client->tail].time = event->time;
		client->buffer[client->tail].type = EV_SYN;
		client->buffer[client->tail].code = SYN_DROPPED;
		client->buffer[client->tail].value = 0;

		client->packet_head = client->tail;
		if (client->use_wake_lock)
			wake_unlock(&client->wake_lock);
	}

	if (event->type == EV_SYN && event->code == SYN_REPORT) {
		client->packet_head = client->head;
		if (client->use_wake_lock)
			wake_lock(&client->wake_lock);
		kill_fasync(&client->fasync, SIGIO, POLL_IN);
	}

	spin_unlock(&client->buffer_lock);
}

#ifdef CONFIG_INPUT_DEV_NS
enum {
	PASS_TO_NONE = 0,
	PASS_TO_A0,
	PASS_TO_AX,
};

static bool evdev_client_from_cml(struct evdev_client *client)
{
	return client->evdev_ns->dev_ns_info.dev_ns == &init_dev_ns;
}

static bool evdev_client_from_a0(struct evdev_client *client)
{
	return !strncmp(client->evdev_ns->dev_ns_info.dev_ns->tag, "a0", 2);
}

/*
 * Timer callback for long pb button presses in aX. In case of a long pb press,
 * signalize to evdev that the button was pressed long and switch back to a0.
 */
static void evdev_pb_pressed_timeout(unsigned long data)
{
	struct evdev_client *client;
	struct evdev *evdev = (struct evdev *)data;
	ktime_t time_mono, time_real;

	// syn event to be passed after key events to seperate events,
	// as key events seem to occur at the same time.
	struct input_event evt_syn;
	struct input_event event;

	// set short press flag to false, as timer expired
	pr_info("pressed_short==%d, set to 0\n", evdev->pb_pressed_short);
	evdev->pb_pressed_short = 0;

	time_mono = ktime_get();
	time_real = ktime_sub(time_mono, ktime_get_monotonic_offset());

	// other attributes are set later
	event.type = EV_KEY;
	event.code = KEY_POWER;
	evt_syn.type = EV_SYN;
	evt_syn.code = SYN_REPORT;

	pr_info("pass to cmld (init)\n");
	rcu_read_lock();
	list_for_each_entry_rcu(client, &evdev->client_list, node) {

		if (!evdev_client_from_cml(client))
			continue;

		event.value = 1;
		evdev_pass_event(client, &event, time_mono, time_real);
		event.value = 0;
		evdev_pass_event(client, &event, time_mono, time_real);
		evt_syn.value = 0;
		evdev_pass_event(client, &evt_syn, time_mono, time_real);

		pr_info("passed to %s\n", client->evdev_ns->dev_ns_info.dev_ns->tag);
		break;
	}
	rcu_read_unlock();

	wake_up_interruptible(&evdev->wait);
	del_timer(&evdev->pb_timer);
}

/*
 * Pass incoming power button events to the forseen container
 */
static void evdev_pass_pb_event(struct evdev *evdev,
				struct input_event *event,
				ktime_t time_mono, ktime_t time_real)
{
	struct evdev_client *client;
	int pass_to = PASS_TO_NONE;
	int value = event->value;

	/* Button presses come from the active container */
	if (!strncmp(active_dev_ns->tag, "a0", 2)) { /* A0 */
		pr_info("pass to a0\n");
		pass_to = PASS_TO_A0;
	} else { /* AX */
		if (value == 1) { /* button down */
			evdev->pb_timer.expires = jiffies + HZ / 2;
			evdev->pb_pressed_short = 1;
			add_timer(&evdev->pb_timer);
			pr_info("timer started\n");
		} else  { /* button up */
			if (evdev->pb_pressed_short) { /* short press */
				pr_info("stop timer and pass to aX\n");
				evdev->pb_pressed_short = 0;
				del_timer(&evdev->pb_timer);
				pass_to = PASS_TO_AX;
			}
		}
	}

	/* button down in aX or long press (long press is handled in timer callback)
	 * button up events are determinative for aX/cmld. We forge the
	 * correspdonding messages when we pass events to aX/cmld */
	if (pass_to == PASS_TO_NONE)
		return;

	// rc_read_(un)lock in calling function
	list_for_each_entry_rcu(client, &evdev->client_list, node) {
		if (pass_to == PASS_TO_A0) { /* just forward to a0 */
			if (!evdev_client_from_a0(client) ||
			    !evdev_client_is_active(client))
				continue;
			evdev_pass_event(client, event, time_mono, time_real);

			pr_info("passed to %s\n",
				client->evdev_ns->dev_ns_info.dev_ns->tag);
		} else if (pass_to == PASS_TO_AX) { /* inform aX in userspace */
			if (evdev_client_from_a0(client) ||
			     !evdev_client_is_active(client))
				continue;
			event->value = 1;
			evdev_pass_event(client, event, time_mono, time_real);
			event->value = 0;
			evdev_pass_event(client, event, time_mono, time_real);

			pr_info("passed to %s\n",
				client->evdev_ns->dev_ns_info.dev_ns->tag);
			break;
		}
	}
}
#endif /* CONFIG_INPUT_DEV_NS */

/*
 * Pass incoming event to all connected clients.
 */
static void evdev_event(struct input_handle *handle,
			unsigned int type, unsigned int code, int value)
{
	struct evdev *evdev = handle->private;
	struct evdev_client *client;
	struct input_event event;
	ktime_t time_mono, time_real;

	if (type == EV_SYN && code == SYN_TIME_SEC) {
		evdev->hw_ts_sec = value;
		return;
	}
	if (type == EV_SYN && code == SYN_TIME_NSEC) {
		evdev->hw_ts_nsec = value;
		return;
	}

	if (evdev->hw_ts_sec != -1 && evdev->hw_ts_nsec != -1)
		time_mono = ktime_set(evdev->hw_ts_sec, evdev->hw_ts_nsec);
	else
		time_mono = ktime_get();

	time_real = ktime_sub(time_mono, ktime_get_monotonic_offset());

	event.type = type;
	event.code = code;
	event.value = value;

	rcu_read_lock();

	client = rcu_dereference(evdev->grab);


#ifdef CONFIG_INPUT_DEV_NS
	if (type == EV_KEY && code == KEY_POWER)
		evdev_pass_pb_event(evdev, &event, time_mono, time_real);
	else
#endif
	if (client)
		evdev_pass_event(client, &event, time_mono, time_real);
	else
		list_for_each_entry_rcu(client, &evdev->client_list, node) {
#ifdef CONFIG_INPUT_DEV_NS
			if (!evdev_client_is_active(client))
				continue;
#endif
			evdev_pass_event(client, &event, time_mono, time_real);
		}

	rcu_read_unlock();

	if (type == EV_SYN && code == SYN_REPORT) {
		evdev->hw_ts_sec = -1;
		evdev->hw_ts_nsec = -1;
		wake_up_interruptible(&evdev->wait);
	}
}

static int evdev_fasync(int fd, struct file *file, int on)
{
	struct evdev_client *client = file->private_data;

	return fasync_helper(fd, file, on, &client->fasync);
}

static int evdev_flush(struct file *file, fl_owner_t id)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	int retval;

	retval = mutex_lock_interruptible(&evdev->mutex);
	if (retval)
		return retval;

	if (!evdev->exist)
		retval = -ENODEV;
	else
		retval = input_flush_device(&evdev->handle, file);

	mutex_unlock(&evdev->mutex);
	return retval;
}

static void evdev_free(struct device *dev)
{
	struct evdev *evdev = container_of(dev, struct evdev, dev);

	input_put_device(evdev->handle.dev);
	kfree(evdev);
}

/*
 * Grabs an event device (along with underlying input device).
 * This function is called with evdev->mutex taken.
 */
static int evdev_grab(struct evdev *evdev, struct evdev_client *client)
{
	int error;

	if (evdev->grab)
		return -EBUSY;

	error = input_grab_device(&evdev->handle);
	if (error)
		return error;

#ifdef CONFIG_INPUT_DEV_NS
	client->grab = true;
#endif
	rcu_assign_pointer(evdev->grab, client);

	return 0;
}

static int evdev_ungrab(struct evdev *evdev, struct evdev_client *client)
{
	if (evdev->grab != client)
		return  -EINVAL;

#ifdef CONFIG_INPUT_DEV_NS
	client->grab = false;
#endif
	rcu_assign_pointer(evdev->grab, NULL);
	synchronize_rcu();
	input_release_device(&evdev->handle);

	return 0;
}

static void evdev_attach_client(struct evdev *evdev,
				struct evdev_client *client)
{
	spin_lock(&evdev->client_lock);
	list_add_tail_rcu(&client->node, &evdev->client_list);
	spin_unlock(&evdev->client_lock);
}

static void evdev_detach_client(struct evdev *evdev,
				struct evdev_client *client)
{
	spin_lock(&evdev->client_lock);
	list_del_rcu(&client->node);
	spin_unlock(&evdev->client_lock);
	synchronize_rcu();
}

static int evdev_open_device(struct evdev *evdev)
{
	int retval;

	retval = mutex_lock_interruptible(&evdev->mutex);
	if (retval)
		return retval;

	if (!evdev->exist)
		retval = -ENODEV;
	else if (!evdev->open++) {
		retval = input_open_device(&evdev->handle);
		if (retval)
			evdev->open--;
	}

	mutex_unlock(&evdev->mutex);
	return retval;
}

static void evdev_close_device(struct evdev *evdev)
{
	mutex_lock(&evdev->mutex);

	if (evdev->exist && !--evdev->open)
		input_close_device(&evdev->handle);

	mutex_unlock(&evdev->mutex);
}

/*
 * Wake up users waiting for IO so they can disconnect from
 * dead device.
 */
static void evdev_hangup(struct evdev *evdev)
{
	struct evdev_client *client;

	spin_lock(&evdev->client_lock);
	list_for_each_entry(client, &evdev->client_list, node)
		kill_fasync(&client->fasync, SIGIO, POLL_HUP);
	spin_unlock(&evdev->client_lock);

	wake_up_interruptible(&evdev->wait);
}

static int evdev_release(struct inode *inode, struct file *file)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;

	mutex_lock(&evdev->mutex);
	if (evdev->grab == client)
		evdev_ungrab(evdev, client);
	mutex_unlock(&evdev->mutex);

#ifdef CONFIG_INPUT_DEV_NS
	evdev_ns_untrack_client(client);
#endif

	evdev_detach_client(evdev, client);
	if (client->use_wake_lock)
		wake_lock_destroy(&client->wake_lock);
	kfree(client);

	evdev_close_device(evdev);
	put_device(&evdev->dev);

	return 0;
}

static unsigned int evdev_compute_buffer_size(struct input_dev *dev)
{
	unsigned int n_events =
		max(dev->hint_events_per_packet * EVDEV_BUF_PACKETS,
		    EVDEV_MIN_BUFFER_SIZE);

	return roundup_pow_of_two(n_events);
}

static int evdev_open(struct inode *inode, struct file *file)
{
	struct evdev *evdev;
	struct evdev_client *client;
	int i = iminor(inode) - EVDEV_MINOR_BASE;
	unsigned int bufsize;
	int error;

	if (i >= EVDEV_MINORS)
		return -ENODEV;

	error = mutex_lock_interruptible(&evdev_table_mutex);
	if (error)
		return error;
	evdev = evdev_table[i];
	if (evdev)
		get_device(&evdev->dev);
	mutex_unlock(&evdev_table_mutex);

	if (!evdev)
		return -ENODEV;

	bufsize = evdev_compute_buffer_size(evdev->handle.dev);

	client = kzalloc(sizeof(struct evdev_client) +
				bufsize * sizeof(struct input_event),
			 GFP_KERNEL);
	if (!client) {
		error = -ENOMEM;
		goto err_put_evdev;
	}

	client->clkid = CLOCK_MONOTONIC;
	client->bufsize = bufsize;
	spin_lock_init(&client->buffer_lock);
	i = snprintf(client->name, sizeof(client->name), "%s-%d",
			dev_name(&evdev->dev), task_tgid_vnr(current));
#ifdef CONFIG_INPUT_DEV_NS
	/* uniquely identify evdev across device namespace */
	snprintf(client->name + i, sizeof(client->name) - i, "[ns:%d]",
		 dev_ns_init_pid(current_dev_ns()));
#endif
	client->evdev = evdev;

#ifdef CONFIG_INPUT_DEV_NS
	error = evdev_ns_track_client(client);
	if (error)
		goto err_free_client;
#endif

	evdev_attach_client(evdev, client);

	error = evdev_open_device(evdev);
	if (error)
		goto err_detach_client;

	file->private_data = client;
	nonseekable_open(inode, file);

	return 0;

 err_detach_client:
	evdev_detach_client(evdev, client);
#ifdef CONFIG_INPUT_DEV_NS
	evdev_ns_untrack_client(client);
 err_free_client:
#endif
	kfree(client);
 err_put_evdev:
	put_device(&evdev->dev);
	return error;
}

static ssize_t evdev_write(struct file *file, const char __user *buffer,
			   size_t count, loff_t *ppos)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	struct input_event event;
	int retval = 0;

	if (count < input_event_size())
		return -EINVAL;

	retval = mutex_lock_interruptible(&evdev->mutex);
	if (retval)
		return retval;

	if (!evdev->exist) {
		retval = -ENODEV;
		goto out;
	}

	do {
		if (input_event_from_user(buffer + retval, &event)) {
			retval = -EFAULT;
			goto out;
		}
		retval += input_event_size();

#ifdef CONFIG_INPUT_DEV_NS
		if (!evdev_client_is_active(client))
			continue;
#endif
		input_inject_event(&evdev->handle,
				   event.type, event.code, event.value);
	} while (retval + input_event_size() <= count);

 out:
	mutex_unlock(&evdev->mutex);
	return retval;
}

static int evdev_fetch_next_event(struct evdev_client *client,
				  struct input_event *event)
{
	int have_event;

	spin_lock_irq(&client->buffer_lock);

	have_event = client->packet_head != client->tail;
	if (have_event) {
		*event = client->buffer[client->tail++];
		client->tail &= client->bufsize - 1;
		if (client->use_wake_lock &&
		    client->packet_head == client->tail)
			wake_unlock(&client->wake_lock);
	}

	spin_unlock_irq(&client->buffer_lock);

	return have_event;
}

static ssize_t evdev_read(struct file *file, char __user *buffer,
			  size_t count, loff_t *ppos)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	struct input_event event;
	int retval = 0;

	if (count < input_event_size())
		return -EINVAL;

	if (!(file->f_flags & O_NONBLOCK)) {
		retval = wait_event_interruptible(evdev->wait,
				client->packet_head != client->tail ||
				!evdev->exist);
		if (retval)
			return retval;
	}

	if (!evdev->exist)
		return -ENODEV;

	while (retval + input_event_size() <= count &&
	       evdev_fetch_next_event(client, &event)) {

		if (input_event_to_user(buffer + retval, &event))
			return -EFAULT;

		retval += input_event_size();
	}

	if (retval == 0 && (file->f_flags & O_NONBLOCK))
		return -EAGAIN;

	return retval;
}

/* No kernel lock - fine */
static unsigned int evdev_poll(struct file *file, poll_table *wait)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	unsigned int mask;

	poll_wait(file, &evdev->wait, wait);

	mask = evdev->exist ? POLLOUT | POLLWRNORM : POLLHUP | POLLERR;
	if (client->packet_head != client->tail)
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

#ifdef CONFIG_COMPAT

#define BITS_PER_LONG_COMPAT (sizeof(compat_long_t) * 8)
#define BITS_TO_LONGS_COMPAT(x) ((((x) - 1) / BITS_PER_LONG_COMPAT) + 1)

#ifdef __BIG_ENDIAN
static int bits_to_user(unsigned long *bits, unsigned int maxbit,
			unsigned int maxlen, void __user *p, int compat)
{
	int len, i;

	if (compat) {
		len = BITS_TO_LONGS_COMPAT(maxbit) * sizeof(compat_long_t);
		if (len > maxlen)
			len = maxlen;

		for (i = 0; i < len / sizeof(compat_long_t); i++)
			if (copy_to_user((compat_long_t __user *) p + i,
					 (compat_long_t *) bits +
						i + 1 - ((i % 2) << 1),
					 sizeof(compat_long_t)))
				return -EFAULT;
	} else {
		len = BITS_TO_LONGS(maxbit) * sizeof(long);
		if (len > maxlen)
			len = maxlen;

		if (copy_to_user(p, bits, len))
			return -EFAULT;
	}

	return len;
}
#else
static int bits_to_user(unsigned long *bits, unsigned int maxbit,
			unsigned int maxlen, void __user *p, int compat)
{
	int len = compat ?
			BITS_TO_LONGS_COMPAT(maxbit) * sizeof(compat_long_t) :
			BITS_TO_LONGS(maxbit) * sizeof(long);

	if (len > maxlen)
		len = maxlen;

	return copy_to_user(p, bits, len) ? -EFAULT : len;
}
#endif /* __BIG_ENDIAN */

#else

static int bits_to_user(unsigned long *bits, unsigned int maxbit,
			unsigned int maxlen, void __user *p, int compat)
{
	int len = BITS_TO_LONGS(maxbit) * sizeof(long);

	if (len > maxlen)
		len = maxlen;

	return copy_to_user(p, bits, len) ? -EFAULT : len;
}

#endif /* CONFIG_COMPAT */

static int str_to_user(const char *str, unsigned int maxlen, void __user *p)
{
	int len;

	if (!str)
		return -ENOENT;

	len = strlen(str) + 1;
	if (len > maxlen)
		len = maxlen;

	return copy_to_user(p, str, len) ? -EFAULT : len;
}

#define OLD_KEY_MAX	0x1ff
static int handle_eviocgbit(struct input_dev *dev,
			    unsigned int type, unsigned int size,
			    void __user *p, int compat_mode)
{
	static unsigned long keymax_warn_time;
	unsigned long *bits;
	int len;

	switch (type) {

	case      0: bits = dev->evbit;  len = EV_MAX;  break;
	case EV_KEY: bits = dev->keybit; len = KEY_MAX; break;
	case EV_REL: bits = dev->relbit; len = REL_MAX; break;
	case EV_ABS: bits = dev->absbit; len = ABS_MAX; break;
	case EV_MSC: bits = dev->mscbit; len = MSC_MAX; break;
	case EV_LED: bits = dev->ledbit; len = LED_MAX; break;
	case EV_SND: bits = dev->sndbit; len = SND_MAX; break;
	case EV_FF:  bits = dev->ffbit;  len = FF_MAX;  break;
	case EV_SW:  bits = dev->swbit;  len = SW_MAX;  break;
	default: return -EINVAL;
	}

	/*
	 * Work around bugs in userspace programs that like to do
	 * EVIOCGBIT(EV_KEY, KEY_MAX) and not realize that 'len'
	 * should be in bytes, not in bits.
	 */
	if (type == EV_KEY && size == OLD_KEY_MAX) {
		len = OLD_KEY_MAX;
		if (printk_timed_ratelimit(&keymax_warn_time, 10 * 1000))
			pr_warning("(EVIOCGBIT): Suspicious buffer size %u, "
				   "limiting output to %zu bytes. See "
				   "http://userweb.kernel.org/~dtor/eviocgbit-bug.html\n",
				   OLD_KEY_MAX,
				   BITS_TO_LONGS(OLD_KEY_MAX) * sizeof(long));
	}

	return bits_to_user(bits, len, size, p, compat_mode);
}
#undef OLD_KEY_MAX

static int evdev_handle_get_keycode(struct input_dev *dev, void __user *p)
{
	struct input_keymap_entry ke = {
		.len	= sizeof(unsigned int),
		.flags	= 0,
	};
	int __user *ip = (int __user *)p;
	int error;

	/* legacy case */
	if (copy_from_user(ke.scancode, p, sizeof(unsigned int)))
		return -EFAULT;

	error = input_get_keycode(dev, &ke);
	if (error)
		return error;

	if (put_user(ke.keycode, ip + 1))
		return -EFAULT;

	return 0;
}

static int evdev_handle_get_keycode_v2(struct input_dev *dev, void __user *p)
{
	struct input_keymap_entry ke;
	int error;

	if (copy_from_user(&ke, p, sizeof(ke)))
		return -EFAULT;

	error = input_get_keycode(dev, &ke);
	if (error)
		return error;

	if (copy_to_user(p, &ke, sizeof(ke)))
		return -EFAULT;

	return 0;
}

static int evdev_handle_set_keycode(struct input_dev *dev, void __user *p)
{
	struct input_keymap_entry ke = {
		.len	= sizeof(unsigned int),
		.flags	= 0,
	};
	int __user *ip = (int __user *)p;

	if (copy_from_user(ke.scancode, p, sizeof(unsigned int)))
		return -EFAULT;

	if (get_user(ke.keycode, ip + 1))
		return -EFAULT;

	return input_set_keycode(dev, &ke);
}

static int evdev_handle_set_keycode_v2(struct input_dev *dev, void __user *p)
{
	struct input_keymap_entry ke;

	if (copy_from_user(&ke, p, sizeof(ke)))
		return -EFAULT;

	if (ke.len > sizeof(ke.scancode))
		return -EINVAL;

	return input_set_keycode(dev, &ke);
}

static int evdev_handle_mt_request(struct input_dev *dev,
				   unsigned int size,
				   int __user *ip)
{
	const struct input_mt_slot *mt = dev->mt;
	unsigned int code;
	int max_slots;
	int i;

	if (get_user(code, &ip[0]))
		return -EFAULT;
	if (!input_is_mt_value(code))
		return -EINVAL;

	max_slots = (size - sizeof(__u32)) / sizeof(__s32);
	for (i = 0; i < dev->mtsize && i < max_slots; i++)
		if (put_user(input_mt_get_value(&mt[i], code), &ip[1 + i]))
			return -EFAULT;

	return 0;
}

static int evdev_enable_suspend_block(struct evdev *evdev,
				      struct evdev_client *client)
{
	if (client->use_wake_lock)
		return 0;

	spin_lock_irq(&client->buffer_lock);
	wake_lock_init(&client->wake_lock, WAKE_LOCK_SUSPEND, client->name);
	client->use_wake_lock = true;
	if (client->packet_head != client->tail)
		wake_lock(&client->wake_lock);
	spin_unlock_irq(&client->buffer_lock);
	return 0;
}

static int evdev_disable_suspend_block(struct evdev *evdev,
				       struct evdev_client *client)
{
	if (!client->use_wake_lock)
		return 0;

	spin_lock_irq(&client->buffer_lock);
	client->use_wake_lock = false;
	spin_unlock_irq(&client->buffer_lock);
	wake_lock_destroy(&client->wake_lock);

	return 0;
}

static long evdev_do_ioctl(struct file *file, unsigned int cmd,
			   void __user *p, int compat_mode)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	struct input_dev *dev = evdev->handle.dev;
	struct input_absinfo abs;
	struct ff_effect effect;
	int __user *ip = (int __user *)p;
	unsigned int i, t, u, v;
	unsigned int size;
	int error;

	/* First we check for fixed-length commands */
	switch (cmd) {

	case EVIOCGVERSION:
		return put_user(EV_VERSION, ip);

	case EVIOCGID:
		if (copy_to_user(p, &dev->id, sizeof(struct input_id)))
			return -EFAULT;
		return 0;

	case EVIOCGREP:
		if (!test_bit(EV_REP, dev->evbit))
			return -ENOSYS;
		if (put_user(dev->rep[REP_DELAY], ip))
			return -EFAULT;
		if (put_user(dev->rep[REP_PERIOD], ip + 1))
			return -EFAULT;
		return 0;

	case EVIOCSREP:
		if (!test_bit(EV_REP, dev->evbit))
			return -ENOSYS;
		if (get_user(u, ip))
			return -EFAULT;
		if (get_user(v, ip + 1))
			return -EFAULT;

#ifdef CONFIG_INPUT_DEV_NS
		if (!evdev_client_is_active(client))
			return 0;
#endif
		input_inject_event(&evdev->handle, EV_REP, REP_DELAY, u);
		input_inject_event(&evdev->handle, EV_REP, REP_PERIOD, v);

		return 0;

	case EVIOCRMFF:
#ifdef CONFIG_INPUT_DEV_NS
		if (!evdev_client_is_active(client))
			return 0;
#endif
		return input_ff_erase(dev, (int)(unsigned long) p, file);

	case EVIOCGEFFECTS:
		i = test_bit(EV_FF, dev->evbit) ?
				dev->ff->max_effects : 0;
		if (put_user(i, ip))
			return -EFAULT;
		return 0;

	case EVIOCGRAB:
#ifdef CONFIG_INPUT_DEV_NS
		if (!evdev_client_is_active(client)) {
			if (p)
				client->grab = true;
			else
				client->grab = false;
			return 0;
		} /* else */
#endif
		if (p)
			return evdev_grab(evdev, client);
		else
			return evdev_ungrab(evdev, client);

	case EVIOCSCLOCKID:
		if (copy_from_user(&i, p, sizeof(unsigned int)))
			return -EFAULT;
		if (i != CLOCK_MONOTONIC && i != CLOCK_REALTIME)
			return -EINVAL;
		client->clkid = i;
		return 0;

	case EVIOCGKEYCODE:
		return evdev_handle_get_keycode(dev, p);

	case EVIOCSKEYCODE:
#ifdef CONFIG_INPUT_DEV_NS
		if (!evdev_client_is_active(client))
			return 0;
#endif
		return evdev_handle_set_keycode(dev, p);

	case EVIOCGKEYCODE_V2:
		return evdev_handle_get_keycode_v2(dev, p);

	case EVIOCSKEYCODE_V2:
		return evdev_handle_set_keycode_v2(dev, p);

	case EVIOCGSUSPENDBLOCK:
		return put_user(client->use_wake_lock, ip);

	case EVIOCSSUSPENDBLOCK:
		if (p)
			return evdev_enable_suspend_block(evdev, client);
		else
			return evdev_disable_suspend_block(evdev, client);
	}

	size = _IOC_SIZE(cmd);

	/* Now check variable-length commands */
#define EVIOC_MASK_SIZE(nr)	((nr) & ~(_IOC_SIZEMASK << _IOC_SIZESHIFT))
	switch (EVIOC_MASK_SIZE(cmd)) {

	case EVIOCGPROP(0):
		return bits_to_user(dev->propbit, INPUT_PROP_MAX,
				    size, p, compat_mode);

	case EVIOCGMTSLOTS(0):
		return evdev_handle_mt_request(dev, size, ip);

	case EVIOCGKEY(0):
		return bits_to_user(dev->key, KEY_MAX, size, p, compat_mode);

	case EVIOCGLED(0):
		return bits_to_user(dev->led, LED_MAX, size, p, compat_mode);

	case EVIOCGSND(0):
		return bits_to_user(dev->snd, SND_MAX, size, p, compat_mode);

	case EVIOCGSW(0):
		return bits_to_user(dev->sw, SW_MAX, size, p, compat_mode);

	case EVIOCGNAME(0):
		return str_to_user(dev->name, size, p);

	case EVIOCGPHYS(0):
		return str_to_user(dev->phys, size, p);

	case EVIOCGUNIQ(0):
		return str_to_user(dev->uniq, size, p);

	case EVIOC_MASK_SIZE(EVIOCSFF):
#ifdef CONFIG_INPUT_DEV_NS
		if (!evdev_client_is_active(client))
			return 0;
#endif
		if (input_ff_effect_from_user(p, size, &effect))
			return -EFAULT;

		error = input_ff_upload(dev, &effect, file);

		if (put_user(effect.id, &(((struct ff_effect __user *)p)->id)))
			return -EFAULT;

		return error;
	}

	/* Multi-number variable-length handlers */
	if (_IOC_TYPE(cmd) != 'E')
		return -EINVAL;

	if (_IOC_DIR(cmd) == _IOC_READ) {

		if ((_IOC_NR(cmd) & ~EV_MAX) == _IOC_NR(EVIOCGBIT(0, 0)))
			return handle_eviocgbit(dev,
						_IOC_NR(cmd) & EV_MAX, size,
						p, compat_mode);

		if ((_IOC_NR(cmd) & ~ABS_MAX) == _IOC_NR(EVIOCGABS(0))) {

			if (!dev->absinfo)
				return -EINVAL;

			t = _IOC_NR(cmd) & ABS_MAX;
			abs = dev->absinfo[t];

			if (copy_to_user(p, &abs, min_t(size_t,
					size, sizeof(struct input_absinfo))))
				return -EFAULT;

			return 0;
		}
	}

	if (_IOC_DIR(cmd) == _IOC_WRITE) {

#ifdef CONFIG_INPUT_DEV_NS
		if (!evdev_client_is_active(client))
			return 0;
#endif
		if ((_IOC_NR(cmd) & ~ABS_MAX) == _IOC_NR(EVIOCSABS(0))) {

			if (!dev->absinfo)
				return -EINVAL;

			t = _IOC_NR(cmd) & ABS_MAX;

			if (copy_from_user(&abs, p, min_t(size_t,
					size, sizeof(struct input_absinfo))))
				return -EFAULT;

			if (size < sizeof(struct input_absinfo))
				abs.resolution = 0;

			/* We can't change number of reserved MT slots */
			if (t == ABS_MT_SLOT)
				return -EINVAL;

			/*
			 * Take event lock to ensure that we are not
			 * changing device parameters in the middle
			 * of event.
			 */
			spin_lock_irq(&dev->event_lock);
			dev->absinfo[t] = abs;
			spin_unlock_irq(&dev->event_lock);

			return 0;
		}
	}

	return -EINVAL;
}

static long evdev_ioctl_handler(struct file *file, unsigned int cmd,
				void __user *p, int compat_mode)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	int retval;

	retval = mutex_lock_interruptible(&evdev->mutex);
	if (retval)
		return retval;

	if (!evdev->exist) {
		retval = -ENODEV;
		goto out;
	}

	retval = evdev_do_ioctl(file, cmd, p, compat_mode);

 out:
	mutex_unlock(&evdev->mutex);
	return retval;
}

static long evdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return evdev_ioctl_handler(file, cmd, (void __user *)arg, 0);
}

#ifdef CONFIG_COMPAT
static long evdev_ioctl_compat(struct file *file,
				unsigned int cmd, unsigned long arg)
{
	return evdev_ioctl_handler(file, cmd, compat_ptr(arg), 1);
}
#endif

static const struct file_operations evdev_fops = {
	.owner		= THIS_MODULE,
	.read		= evdev_read,
	.write		= evdev_write,
	.poll		= evdev_poll,
	.open		= evdev_open,
	.release	= evdev_release,
	.unlocked_ioctl	= evdev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= evdev_ioctl_compat,
#endif
	.fasync		= evdev_fasync,
	.flush		= evdev_flush,
	.llseek		= no_llseek,
};

static int evdev_install_chrdev(struct evdev *evdev)
{
	/*
	 * No need to do any locking here as calls to connect and
	 * disconnect are serialized by the input core
	 */
	evdev_table[evdev->minor] = evdev;
	return 0;
}

static void evdev_remove_chrdev(struct evdev *evdev)
{
	/*
	 * Lock evdev table to prevent race with evdev_open()
	 */
	mutex_lock(&evdev_table_mutex);
	evdev_table[evdev->minor] = NULL;
	mutex_unlock(&evdev_table_mutex);
}

/*
 * Mark device non-existent. This disables writes, ioctls and
 * prevents new users from opening the device. Already posted
 * blocking reads will stay, however new ones will fail.
 */
static void evdev_mark_dead(struct evdev *evdev)
{
	mutex_lock(&evdev->mutex);
	evdev->exist = false;
	mutex_unlock(&evdev->mutex);
}

static void evdev_cleanup(struct evdev *evdev)
{
	struct input_handle *handle = &evdev->handle;

	evdev_mark_dead(evdev);
	evdev_hangup(evdev);
	evdev_remove_chrdev(evdev);

	/* evdev is marked dead so no one else accesses evdev->open */
	if (evdev->open) {
		input_flush_device(handle, NULL);
		input_close_device(handle);
	}
}

/*
 * Create new evdev device. Note that input core serializes calls
 * to connect and disconnect so we don't need to lock evdev_table here.
 */
static int evdev_connect(struct input_handler *handler, struct input_dev *dev,
			 const struct input_device_id *id)
{
	struct evdev *evdev;
	int minor;
	int error;

	for (minor = 0; minor < EVDEV_MINORS; minor++)
		if (!evdev_table[minor])
			break;

	if (minor == EVDEV_MINORS) {
		pr_err("no more free evdev devices\n");
		return -ENFILE;
	}

	evdev = kzalloc(sizeof(struct evdev), GFP_KERNEL);
	if (!evdev)
		return -ENOMEM;

	INIT_LIST_HEAD(&evdev->client_list);
	spin_lock_init(&evdev->client_lock);
	mutex_init(&evdev->mutex);
	init_waitqueue_head(&evdev->wait);

	dev_set_name(&evdev->dev, "event%d", minor);
	evdev->exist = true;
	evdev->minor = minor;
	evdev->hw_ts_sec = -1;
	evdev->hw_ts_nsec = -1;

#ifdef CONFIG_INPUT_DEV_NS
	/* Power button handler */
	setup_timer(&evdev->pb_timer, evdev_pb_pressed_timeout,
		    (unsigned long)evdev);
#endif

	evdev->handle.dev = input_get_device(dev);
	evdev->handle.name = dev_name(&evdev->dev);
	evdev->handle.handler = handler;
	evdev->handle.private = evdev;

	evdev->dev.devt = MKDEV(INPUT_MAJOR, EVDEV_MINOR_BASE + minor);
	evdev->dev.class = &input_class;
	evdev->dev.parent = &dev->dev;
	evdev->dev.release = evdev_free;
	device_initialize(&evdev->dev);

	error = input_register_handle(&evdev->handle);
	if (error)
		goto err_free_evdev;

	error = evdev_install_chrdev(evdev);
	if (error)
		goto err_unregister_handle;

	error = device_add(&evdev->dev);
	if (error)
		goto err_cleanup_evdev;

	return 0;

 err_cleanup_evdev:
	evdev_cleanup(evdev);
 err_unregister_handle:
	input_unregister_handle(&evdev->handle);
 err_free_evdev:
	put_device(&evdev->dev);
	return error;
}

static void evdev_disconnect(struct input_handle *handle)
{
	struct evdev *evdev = handle->private;

	device_del(&evdev->dev);
	evdev_cleanup(evdev);
	input_unregister_handle(handle);
	put_device(&evdev->dev);
}

static const struct input_device_id evdev_ids[] = {
	{ .driver_info = 1 },	/* Matches all devices */
	{ },			/* Terminating zero entry */
};

MODULE_DEVICE_TABLE(input, evdev_ids);

static struct input_handler evdev_handler = {
	.event		= evdev_event,
	.connect	= evdev_connect,
	.disconnect	= evdev_disconnect,
	.fops		= &evdev_fops,
	.minor		= EVDEV_MINOR_BASE,
	.name		= "evdev",
	.id_table	= evdev_ids,
};

static int __init evdev_init(void)
{
	int ret;

	ret = input_register_handler(&evdev_handler);
	if (ret < 0)
		return ret;
#ifdef CONFIG_INPUT_DEV_NS
	ret = DEV_NS_REGISTER(evdev, "event dev");
	if (ret < 0) {
		input_unregister_handler(&evdev_handler);
		return ret;
	}
#endif
	return 0;
}

static void __exit evdev_exit(void)
{
#ifdef CONFIG_INPUT_DEV_NS
	DEV_NS_UNREGISTER(evdev);
#endif
	input_unregister_handler(&evdev_handler);
}

module_init(evdev_init);
module_exit(evdev_exit);

MODULE_AUTHOR("Vojtech Pavlik <vojtech@ucw.cz>");
MODULE_DESCRIPTION("Input driver event char devices");
MODULE_LICENSE("GPL");
