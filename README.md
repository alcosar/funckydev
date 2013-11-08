funckydev
=========

exercise in linux kernel device driver programming

This a linux kernel driver that keeps record of all running userspace tasks.
It records task name, path to the task executable, the number of times task
was running during module's life.
To track what task is running kprobe(jprobe) to do_execve call is used.
Kprobe should be enabled in the kernel wich is the case for Ubuntu kernels
starting at least from k3.2 until now(3.11):

$ cat /boot/config-3.11.0-12-generic | grep -i kprobe
CONFIG_KPROBES=y
CONFIG_KPROBES_ON_FTRACE=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KPROBES_ON_FTRACE=y
CONFIG_KPROBE_EVENT=y
# CONFIG_KPROBES_SANITY_TEST is not set

The node in /dev is created so the user can 'cat' and 'echo' to it.
The user can write to /dev/funckydev name of the process, and then
read records about it.

The current record could be seen in debugfs also:
$ sudo cat /sys/kernel/debug/main_funcky 
         insmod :  1 : /bin/kmod
           sudo :  1 : /usr/bin/sudo
           sshd :  1 : /usr/sbin/sshd
       dhclient :  1 : /sbin/dhclient
         pickup :  1 : /usr/lib/postfix/pickup
           qmgr :  1 : /usr/lib/postfix/qmgr
    gvfsd-trash :  1 : /usr/lib/gvfs/gvfsd-trash
    dbus-launch :  1 : /usr/bin/dbus-launch

The user can clear all the records or a record for a specific task using
ioctl system call.
