#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

struct funcky_t {
	struct cdev cdev;
	int count;	/* only one device could be served */
};

static struct funcky_t funcky;
static char app_name[TASK_COMM_LEN];
static char clear_name[TASK_COMM_LEN];
static struct class *devclass;

struct db_item {
	char *name;	/* application name */
	char *path;	/* application path */
	int count;
};

struct path_list {
	struct list_head list;
	char name[TASK_COMM_LEN];
	char path[0];
};

static struct list_head path_list_head;
static struct dentry *debug_dentry;

static struct file *my_get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

	/* We need mmap_sem to protect against races with removal of
	 * VM_EXECUTABLE vmas */
	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if (exe_file)
		get_file(exe_file);
	up_read(&mm->mmap_sem);
	return exe_file;
}

static int get_exe_path(struct task_struct *task)
{
	struct mm_struct *mm;
        struct file *exe_file;
	char *pathbuf;
	char *path;
	int ret = 0;
	size_t len;
	struct path_list *plist;

	mm = get_task_mm(task);
	if (!mm)
		/* kernel threads do not have mm */
		return ret;
	exe_file = my_get_mm_exe_file(mm);
	if (!exe_file) {
		printk("path unknown\n");
		return 0;
	}

	pathbuf = kmalloc(PATH_MAX, GFP_TEMPORARY);
	if (!pathbuf) {
		ret = -ENOMEM;
		goto put_exe_file;
	}

	path = d_path(&exe_file->f_path, pathbuf, PATH_MAX);
	if (IS_ERR(path)) {
		ret = PTR_ERR(path);
		goto free_buf;
	}

	len = strlen(path) + 1;
	plist = kmalloc(sizeof(*plist) + len, GFP_KERNEL);
	if (!plist) {
		ret = -ENOMEM;
		goto free_buf;
	}
	strncpy(plist->path, path, len);
	get_task_comm(plist->name, task);
	list_add(&plist->list, &path_list_head);
	printk("%16s : %s\n", plist->name, plist->path);

free_buf:
	kfree(pathbuf);
put_exe_file:
	fput(exe_file);
	return ret;
}

static void free_used_mem(void)
{
	struct path_list *p, *tmp;

	list_for_each_entry_safe(p, tmp, &path_list_head, list) {
		list_del(&p->list);
		kfree(p);
	}
}

static int funcky_open(struct inode *inode, struct file *filp)
{
	if (funcky.count)
		return -EBUSY;
	funcky.count++;

	return 0;
}


int funcky_release(struct inode *inode, struct file *filp)
{
	funcky.count = 0;

	return 0;
}

ssize_t funcky_read(struct file *filp, char __user *buf, size_t count,
			loff_t *f_pos)
{
	int res = 0;

	return res;
}

ssize_t funcky_write(struct file *filp, const char __user *buf, size_t count,
			loff_t *f_pos)
{
	int res = 0;
	size_t len = min(sizeof(app_name), count);

	res = copy_from_user(app_name, (void*)buf, len);
	if (res)
		return -EFAULT;
	app_name[len - 1] = '\0';

	return len;
}

#define CLEAR_DB	1	/* clear data base */
#define CLEAR_NAME	2	/* clear info for specific name */

long funcky_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int res = 0;

	switch (cmd) {
	case CLEAR_DB:
		break;
	case CLEAR_NAME:
		res = copy_from_user(clear_name, (char *)arg, sizeof(clear_name));
		break;
	default:
		break;
	}

	return res;
}

static struct file_operations funcky_fops = {
	.owner =     THIS_MODULE,
	.open =	     funcky_open,
	.release =   funcky_release,
	.read =	     funcky_read,
	.write =     funcky_write,
	.unlocked_ioctl = funcky_ioctl,
};

static int funcky_dump(struct seq_file *sf, void *private)
{
	struct path_list *plist;

	list_for_each_entry(plist, &path_list_head, list) {
		seq_printf(sf, "%15s : %s\n", plist->name, plist->path);
	}

	return 0;
}

static int funcky_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, funcky_dump, NULL);
}

static const struct file_operations funcky_debug_fops = {
	.open = funcky_debug_open,
	.release = single_release,
	.read = seq_read,
};

static int __init funcky_init(void) {
	int res;
	dev_t dev;
	struct device *cd;
	struct task_struct *task = current;
	int ret;

	res = alloc_chrdev_region(&dev, 0, 1, "funcky_dev");
	if (res < 0) {
		pr_err("%s: %d failed\n", __func__, __LINE__);
		return res;
	}

	cdev_init(&funcky.cdev, &funcky_fops);
	funcky.cdev.owner = THIS_MODULE;
	funcky.cdev.ops = &funcky_fops;
	res = cdev_add(&funcky.cdev, dev, 1);
	if (res) {
		pr_err("%s: %d Error: %d", __func__, __LINE__, res);
		goto err;
	}

	/* create node in /dev/funckydev */
	devclass = class_create(THIS_MODULE, "funcky_class");
	cd = device_create(devclass, NULL, dev, "%s", "funckydev");
	if (IS_ERR(cd)) {
		res = PTR_ERR(cd);
		pr_err("%s: %d Error: %d", __func__, __LINE__, res);
		goto del_dev;
	}

	INIT_LIST_HEAD(&path_list_head);

	for_each_process(task) {
		ret = get_exe_path(task);
		if (ret) {
			free_used_mem();
			return -ENOMEM;
		}
	}
	debug_dentry = debugfs_create_file("main_funcky",
				S_IRUGO, NULL, NULL, &funcky_debug_fops);
	if (IS_ERR_OR_NULL(debug_dentry))
		pr_err("%s: failed to create main_funcky file\n", __func__);

	printk("%s\n", __func__);
	return 0;

del_dev:
	cdev_del(&funcky.cdev);
err:
	unregister_chrdev_region(dev, 1);
	return res;
}

static void __exit funcky_exit(void)
{
	printk("%s\n", __func__);
	free_used_mem();
	debugfs_remove(debug_dentry);
	device_destroy(devclass, funcky.cdev.dev);
	class_destroy(devclass);
	cdev_del(&funcky.cdev);
	unregister_chrdev_region(funcky.cdev.dev, 1);
}

module_init(funcky_init);
module_exit(funcky_exit);

MODULE_LICENSE("GPL");
