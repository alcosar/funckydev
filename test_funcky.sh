#!/bin/sh

sudo insmod main_funcky.ko

# test device node creation in /dev
if [ -c /dev/funckydev ]; then
	echo "1. funckydev created ... success"
else
	echo failed to create dev node
	exit -1
fi

# test file creation in debugfs
sudo cat /sys/kernel/debug/main_funcky > /dev/null
if [ $? != 0 ]; then
	echo "failed to create entry in debugfs"
else
	echo "2. entry in debugfs created ... success"
fi

# test ioctl clear specific file from data base
./ioctl 2 init
if [ $? = 0 ]; then
	echo "3. info for 'init' process removed from data base ... success"
else
	echo "'ioctl 2 init' failed"
	exit -1
fi

# test write call
echo "getty" > /dev/funckydev
if [ $? = 0 ]; then
	echo "4. 'getty' is written to /dev/funckydev ... success"
else
	echo "write to /dev/funckydev failed"
	exit -1
fi

# test read call
cat /dev/funckydev | grep "getty" > /dev/null
if [ $? = 0 ]; then
	echo "5. read 'getty' ... success"
else
	echo "read of /dev/funckydev failed"
	exit -1
fi

# test clear all data base records
./ioctl 1
if [ $? = 0 ]; then
	echo "6. all record in data base are cleared ... success"
else
	echo "'ioctl 1' failed"
	exit -1
fi

sudo rmmod main_funcky
if [ $? = 0 ]; then
	echo "7. removing driver ... success"
else
	echo "rmoving driver failed"
	exit -1
fi

echo "all tests passed"
