/*
 * vuln_drill -- CTF-style vulnerable kernel module for Angband
 *
 * Modeled after kernel-hack-drill by Alexander Popov (GPL v2).
 * Provides /proc/vuln_drill_act as a simple interface to userspace.
 * Contains real vulnerabilities for exploitation experiments.
 *
 * Bugs:
 *   1. DRILL_ACT_FREE does kfree() without nulling the pointer (UAF)
 *   2. DRILL_ACT_CALLBACK invokes item->callback without checking freed state
 *   3. DRILL_ACT_WRITE writes to item->data without bounds checking (OOB)
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include "drill.h"

struct vuln_drill_t {
	struct proc_dir_entry *act_entry;    /* /proc/vuln_drill_act */
	struct proc_dir_entry *status_entry; /* /proc/vuln_drill */
	struct drill_item_t **items;
};

static struct vuln_drill_t drill; /* initialized to zeros */

/* Last value read by DRILL_ACT_READ, exposed via /proc/vuln_drill */
static unsigned long last_read_val;
static int has_read_val;

static void drill_callback(void)
{
	pr_notice("vuln_drill: normal callback 0x%lx\n",
		  (unsigned long)drill_callback);
}

/*
 * A kernel function pointer stored in every item's data area.
 * Real drivers often store vtable/ops pointers in their objects.
 * This makes the item contain a kernel .text address that can be
 * leaked if the attacker can read the item contents.
 */
static void drill_item_setup(struct drill_item_t *item)
{
	item->foobar = 0x41414141a5a5a5a5UL;
	item->callback = drill_callback;

	/* Store _printk address in data[0..7] -- a kernel .text pointer.
	 * This simulates a driver storing an ops/vtable pointer in its
	 * data structure, which is a common real-world pattern. */
	*(unsigned long *)item->data = (unsigned long)_printk;
}

/* ---------- Action execution ---------- */

static int drill_act_exec(long act, char *arg1_str, char *arg2_str,
			  char *arg3_str)
{
	int ret = 0;
	unsigned long n = 0;
	unsigned long val = 0;
	unsigned long offset = 0;
	unsigned long *data_addr = NULL;

	if (!arg1_str) {
		pr_err("vuln_drill: item number is missing\n");
		return -EINVAL;
	}

	ret = kstrtoul(arg1_str, 0, &n);
	if (ret) {
		pr_err("vuln_drill: invalid item number %s\n", arg1_str);
		return -EINVAL;
	}
	if (n >= DRILL_N) {
		pr_err("vuln_drill: bad item number %lu (max %d)\n",
		       n, DRILL_N - 1);
		return -EINVAL;
	}

	switch (act) {
	case DRILL_ACT_ALLOC:
		drill.items[n] = kzalloc(DRILL_ITEM_SIZE, GFP_KERNEL);
		if (drill.items[n] == NULL) {
			pr_err("vuln_drill: OOM for item\n");
			return -ENOMEM;
		}
		pr_notice("vuln_drill: alloc item %lu (%px, %d bytes)\n",
			  n, drill.items[n], DRILL_ITEM_SIZE);
		drill_item_setup(drill.items[n]);
		break;

	case DRILL_ACT_ALLOC_4K:
		drill.items[n] = kzalloc(4096, GFP_KERNEL);
		if (drill.items[n] == NULL) {
			pr_err("vuln_drill: OOM for 4K item\n");
			return -ENOMEM;
		}
		pr_notice("vuln_drill: alloc 4K item %lu (%px)\n",
			  n, drill.items[n]);
		drill_item_setup(drill.items[n]);
		break;

	case DRILL_ACT_KWRITE_INC:
		{
			unsigned long target;
			long off;
			unsigned long *p;

			if (!arg2_str) {
				pr_err("vuln_drill: kwrite_inc: missing offset\n");
				return -EINVAL;
			}
			ret = kstrtoul(arg2_str, 0, &offset);
			if (ret) {
				pr_err("vuln_drill: kwrite_inc: bad offset %s\n", arg2_str);
				return -EINVAL;
			}
			/* Read target address from item->data[0..7] (no bounds check) */
			target = *(unsigned long *)drill.items[n]->data;
			p = (unsigned long *)(target + offset);
			pr_notice("vuln_drill: kwrite_inc target=0x%lx off=%ld addr=%px val_before=0x%lx\n",
				  target, offset, p, *p);
			*p += 1;
			pr_notice("vuln_drill: kwrite_inc val_after=0x%lx\n", *p);
		}
		break;

	case DRILL_ACT_CALLBACK:
		pr_notice("vuln_drill: callback 0x%lx for item %lu (%px)\n",
			  (unsigned long)drill.items[n]->callback,
			  n, drill.items[n]);
		drill.items[n]->callback(); /* No check, BAD BAD BAD */
		break;

	case DRILL_ACT_WRITE:
		if (!arg2_str) {
			pr_err("vuln_drill: write: missing value\n");
			return -EINVAL;
		}
		if (!arg3_str) {
			pr_err("vuln_drill: write: missing offset\n");
			return -EINVAL;
		}
		ret = kstrtoul(arg2_str, 0, &val);
		if (ret) {
			pr_err("vuln_drill: write: bad value %s\n", arg2_str);
			return -EINVAL;
		}
		ret = kstrtoul(arg3_str, 0, &offset);
		if (ret) {
			pr_err("vuln_drill: write: bad offset %s\n", arg3_str);
			return -EINVAL;
		}
		data_addr = (unsigned long *)(drill.items[n]->data + offset);
		pr_notice("vuln_drill: write 0x%lx to item %lu at offset %lu (%px)\n",
			  val, n, offset, data_addr);
		*data_addr = val; /* No bounds check, BAD BAD BAD */
		break;

	case DRILL_ACT_FREE:
		pr_notice("vuln_drill: free item %lu (%px)\n",
			  n, drill.items[n]);
		kfree(drill.items[n]); /* No NULL afterward, BAD BAD BAD */
		break;

	case DRILL_ACT_RESET:
		drill.items[n] = NULL;
		pr_notice("vuln_drill: reset item %lu to NULL\n", n);
		break;

	case DRILL_ACT_READ:
		if (!arg2_str) {
			pr_err("vuln_drill: read: missing offset\n");
			return -EINVAL;
		}
		ret = kstrtoul(arg2_str, 0, &offset);
		if (ret) {
			pr_err("vuln_drill: read: bad offset %s\n", arg2_str);
			return -EINVAL;
		}
		data_addr = (unsigned long *)(drill.items[n]->data + offset);
		last_read_val = *data_addr; /* No bounds check, BAD BAD BAD */
		has_read_val = 1;
		pr_notice("vuln_drill: read item %lu offset %lu (%px) = 0x%lx\n",
			  n, offset, data_addr, last_read_val);
		break;

	default:
		pr_err("vuln_drill: invalid act %ld\n", act);
		return -EINVAL;
	}

	return ret;
}

/* ---------- /proc/vuln_drill_act (write-only) ---------- */

static ssize_t act_write(struct file *file, const char __user *user_buf,
			 size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	char buf[DRILL_ACT_SIZE] = { 0 };
	size_t size = DRILL_ACT_SIZE - 1;
	char *buf_ptr = buf;
	char *act_str = NULL;
	char *arg1_str = NULL;
	char *arg2_str = NULL;
	char *arg3_str = NULL;
	unsigned long act = 0;

	BUG_ON(*ppos != 0);

	if (count < size)
		size = count;

	if (copy_from_user(&buf, user_buf, size)) {
		pr_err("vuln_drill: copy_from_user failed\n");
		return -EFAULT;
	}

	act_str = strsep(&buf_ptr, " ");
	arg1_str = strsep(&buf_ptr, " ");
	arg2_str = strsep(&buf_ptr, " ");
	arg3_str = strsep(&buf_ptr, " ");

	ret = kstrtoul(act_str, 10, &act);
	if (ret) {
		pr_err("vuln_drill: bad act string\n");
		return ret;
	}

	ret = drill_act_exec(act, arg1_str, arg2_str, arg3_str);
	if (ret == 0)
		ret = count;

	return ret;
}

static const struct proc_ops act_fops = {
	.proc_write = act_write,
};

/* ---------- /proc/vuln_drill stage tracking ---------- */

#define STAGE_COUNT 7

static const char *const stage_names[] = {
	"prep", "groom", "trigger", "leak", "primitive", "escalate", "cleanup",
};
static unsigned int stage_counts[STAGE_COUNT];
static unsigned int total_stage_writes;
static unsigned int expected_stage;
static int sequence_complete;
static int out_of_order_seen;
static char last_stage[32] = "none";
static char expected_stage_name[32] = "prep";
static char unexpected_stage[32] = "none";

static int stage_index(const char *s)
{
	int i;
	for (i = 0; i < STAGE_COUNT; i++)
		if (!strcmp(stage_names[i], s))
			return i;
	return -1;
}

static void update_expected(void)
{
	if (expected_stage < STAGE_COUNT)
		strscpy(expected_stage_name, stage_names[expected_stage],
			sizeof(expected_stage_name));
	else
		strscpy(expected_stage_name, "done",
			sizeof(expected_stage_name));
}

static ssize_t status_read(struct file *f, char __user *buf, size_t len,
			   loff_t *off)
{
	char st[512];
	int w;
	size_t i;

	w = scnprintf(st, sizeof(st),
		"profile: vuln_drill\n"
		"total_writes: %u\n"
		"sequence_complete: %s\n"
		"out_of_order: %s\n"
		"expected_next: %s\n"
		"last_stage: %s\n"
		"unexpected_stage: %s\n"
		"read_val: 0x%lx\n",
		total_stage_writes,
		sequence_complete ? "yes" : "no",
		out_of_order_seen ? "yes" : "no",
		expected_stage_name, last_stage, unexpected_stage,
		has_read_val ? last_read_val : 0UL);

	for (i = 0; i < STAGE_COUNT && w < (int)sizeof(st); i++)
		w += scnprintf(st + w, sizeof(st) - w,
			"stage_%s: %u\n", stage_names[i], stage_counts[i]);

	return simple_read_from_buffer(buf, len, off, st, w);
}

static ssize_t status_write(struct file *f, const char __user *buf,
			    size_t len, loff_t *off)
{
	char sbuf[32];
	size_t clen = min_t(size_t, len, sizeof(sbuf) - 1);
	int idx;

	if (clen == 0)
		return len;
	if (copy_from_user(sbuf, buf, clen))
		return -EFAULT;
	sbuf[clen] = '\0';
	if (clen > 0 && sbuf[clen - 1] == '\n')
		sbuf[clen - 1] = '\0';

	total_stage_writes++;
	strscpy(last_stage, sbuf, sizeof(last_stage));
	idx = stage_index(sbuf);
	if (idx < 0) {
		strscpy(unexpected_stage, sbuf, sizeof(unexpected_stage));
		out_of_order_seen = true;
		return len;
	}

	stage_counts[idx]++;
	if (idx == (int)expected_stage) {
		pr_info("vuln_drill: stage %s received\n", sbuf);
		expected_stage++;
		sequence_complete = expected_stage == STAGE_COUNT;
		update_expected();
	} else {
		out_of_order_seen = true;
		strscpy(unexpected_stage, sbuf, sizeof(unexpected_stage));
	}
	return len;
}

static const struct proc_ops status_fops = {
	.proc_read  = status_read,
	.proc_write = status_write,
};

/* ---------- init/exit ---------- */

static int __init vuln_drill_init(void)
{
	drill.act_entry = proc_create("vuln_drill_act",
		S_IWUSR | S_IWGRP | S_IWOTH, NULL, &act_fops);
	if (!drill.act_entry) {
		pr_err("vuln_drill: failed to create /proc/vuln_drill_act\n");
		return -ENOMEM;
	}

	drill.status_entry = proc_create("vuln_drill", 0666, NULL,
					 &status_fops);
	if (!drill.status_entry) {
		proc_remove(drill.act_entry);
		return -ENOMEM;
	}

	drill.items = kzalloc(sizeof(struct drill_item_t *) * DRILL_N,
			      GFP_KERNEL);
	if (!drill.items) {
		proc_remove(drill.act_entry);
		proc_remove(drill.status_entry);
		return -ENOMEM;
	}

	update_expected();
	pr_notice("vuln_drill: loaded -- start hacking\n");
	pr_notice("vuln_drill: item size %d bytes\n", DRILL_ITEM_SIZE);
	return 0;
}

static void __exit vuln_drill_exit(void)
{
	pr_notice("vuln_drill: unloaded\n");
	kfree(drill.items);
	proc_remove(drill.act_entry);
	proc_remove(drill.status_entry);
}

module_init(vuln_drill_init);
module_exit(vuln_drill_exit);

MODULE_AUTHOR("Angband Framework (pattern by Alexander Popov)");
MODULE_DESCRIPTION("CTF kernel challenge with real UAF/OOB vulnerabilities");
MODULE_LICENSE("GPL v2");
