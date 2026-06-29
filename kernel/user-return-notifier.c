// SPDX-License-Identifier: GPL-2.0-only

#include <linux/user-return-notifier.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/export.h>

static DEFINE_PER_CPU(struct hlist_head, return_notifier_list);

/* C wrappers for inline/macro primitives callable from Rust */
void urn_set_tif_notify(void)
{
	set_tsk_thread_flag(current, TIF_USER_RETURN_NOTIFY);
}
void urn_clear_tif_notify(void)
{
	clear_tsk_thread_flag(current, TIF_USER_RETURN_NOTIFY);
}
void urn_hlist_add_head(struct user_return_notifier *urn)
{
	hlist_add_head(&urn->link, this_cpu_ptr(&return_notifier_list));
}
void urn_hlist_del(struct user_return_notifier *urn)
{
	hlist_del(&urn->link);
}
bool urn_hlist_empty(void)
{
	return hlist_empty(this_cpu_ptr(&return_notifier_list));
}

/* Calls registered user return notifiers */
void fire_user_return_notifiers(void)
{
	struct user_return_notifier *urn;
	struct hlist_node *tmp2;
	struct hlist_head *head;

	head = &get_cpu_var(return_notifier_list);
	hlist_for_each_entry_safe(urn, tmp2, head, link)
		urn->on_user_return(urn);
	put_cpu_var(return_notifier_list);
}

/* Rust-implemented functions */
void user_return_notifier_register(struct user_return_notifier *urn);
EXPORT_SYMBOL_GPL(user_return_notifier_register);
void user_return_notifier_unregister(struct user_return_notifier *urn);
EXPORT_SYMBOL_GPL(user_return_notifier_unregister);
