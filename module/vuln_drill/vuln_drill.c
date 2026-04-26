#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define PROC_NAME "vuln_drill"
#define IOCTL_TRIGGER 0xDEADBEEF

static char *vulnerable_buf;

static ssize_t proc_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
    printk(KERN_INFO "vuln_drill: trigger received\n");
    /* UAF and OOB primitives will be added here */
    if (len > 0 && !vulnerable_buf) {
        vulnerable_buf = kmalloc(128, GFP_KERNEL);
    }
    return len;
}

static long vuln_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    if (cmd == IOCTL_TRIGGER) {
        printk(KERN_INFO "vuln_drill: ioctl trigger - bug primitive active\n");
        /* Configurable bug injection point for different exploit stages */
    }
    return 0;
}

static const struct proc_ops proc_fops = {
    .proc_write = proc_write,
    .proc_ioctl = vuln_ioctl,
};

static int __init vuln_drill_init(void)
{
    proc_create(PROC_NAME, 0666, NULL, &proc_fops);
    printk(KERN_INFO "vuln_drill: Kernel exploit development module loaded\n");
    printk(KERN_INFO "  Stages supported: grooming, trigger, dirty_cred\n");
    return 0;
}

static void __exit vuln_drill_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "vuln_drill: Module unloaded\n");
}

module_init(vuln_drill_init);
module_exit(vuln_drill_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Angband Framework");
MODULE_DESCRIPTION("Vulnerable module for kernel exploit development and stage testing");