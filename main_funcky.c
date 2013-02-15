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
	atomic_t count;	/* only one device can be served */
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
	int count;
	char name[TASK_COMM_LEN];
	char path[0];
};

static struct list_head path_list_head;
static DEFINE_MUTEX(path_list_lock);
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

static struct path_list *lookup(char *name)
{
	struct path_list *p;
	struct path_list *item = NULL;

	if (!name)
		return NULL;

	mutex_lock(&path_list_lock);
	list_for_each_entry(p, &path_list_head, list) {
		if (!strcmp(name, p->name)) {
			item = p;
			break;
		}
	}
	mutex_unlock(&path_list_lock);

	return item;
}

static int build_tasks_database(struct task_struct *task)
{
	struct mm_struct *mm;
        struct file *exe_file;
	char *pathbuf;
	char *path;
	char task_name[TASK_COMM_LEN];
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

	get_task_comm(task_name, task);

	/* check if we already have record for this task */
	plist = lookup(task_name);
	if (plist) {
		++plist->count;
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
	len = strlen(task_name) + 1;
	strncpy(plist->name, task_name, len);
	plist->count = 1;
	list_add(&plist->list, &path_list_head);

free_buf:
	kfree(pathbuf);
put_exe_file:
	fput(exe_file);
	return ret;
}

static void free_used_mem(void)
{
	struct path_list *p, *tmp;

	mutex_lock(&path_list_lock);
	list_for_each_entry_safe(p, tmp, &path_list_head, list) {
		list_del(&p->list);
		kfree(p);
	}
	mutex_unlock(&path_list_lock);
}

static int funcky_open(struct inode *inode, struct file *filp)
{
	if (!atomic_dec_and_test(&funcky.count))
		return -EBUSY;

	return 0;
}

static int funcky_release(struct inode *inode, struct file *filp)
{
	atomic_set(&funcky.count, 1);

	return 0;
}

static ssize_t funcky_read(struct file *filp, char __user *buf, size_t count,
			loff_t *f_pos)
{
	struct path_list *p;
	size_t len;
	char *pbuf;
	int ret;

	p = lookup(app_name);
	if (!p)
		return -EINVAL;

	len = strlen(p->path) + 1;
	if (*f_pos != 0)
		return 0;
	pbuf = kmalloc(len, GFP_TEMPORARY);
	if (!pbuf)
		return -ENOMEM;
	strncpy(pbuf, p->path, len);
	pbuf[len - 1] = '\n';
	if (copy_to_user(buf, pbuf, len)) {
		ret = -EFAULT;
		goto ret;
	}
	*f_pos += len;
	ret = len;
ret:
	kfree(pbuf);
	return ret;
}

static ssize_t funcky_write(struct file *filp, const char __user *buf, size_t count,
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

#define CLEAR_DB	_IOW('h', 1, char [16])	/* clear data base */
#define CLEAR_NAME	_IOW('h', 2, char [16])	/* clear info for specific name */

long funcky_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int res = 0;
	struct path_list *p;

	if ((_IOC_TYPE(cmd) != 'h'))
		return -ENOTTY;
	switch (cmd) {
	case CLEAR_DB:
		free_used_mem();
		break;
	case CLEAR_NAME:
		res = copy_from_user(clear_name, (char *)arg, sizeof(clear_name));
		if (res)
			return -EFAULT;
		p = lookup(clear_name);
		if (!p)
			return -EINVAL;
		else {
			list_del(&p->list);
			kfree(p);
		}
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

	mutex_lock(&path_list_lock);
	list_for_each_entry(plist, &path_list_head, list) {
		seq_printf(sf, "%15s : %2d : %s\n",
			   plist->name, plist->count, plist->path);
	}
	mutex_unlock(&path_list_lock);

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
	atomic_set(&funcky.count, 1);

	/* create node in /dev/funckydev */
	devclass = class_create(THIS_MODULE, "funcky_class");
	cd = device_create(devclass, NULL, dev, "%s", "funckydev");
	if (IS_ERR(cd)) {
		res = PTR_ERR(cd);
		pr_err("%s: %d Error: %d", __func__, __LINE__, res);
		goto del_dev;
	}

	INIT_LIST_HEAD(&path_list_head);
	mutex_init(&path_list_lock);

	for_each_process(task) {
		ret = build_tasks_database(task);
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
