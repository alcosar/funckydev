#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define device		"/dev/funckydev"

#define CLEAR_DB	_IOW('h', 1, char [16])	/* clear data base */
#define CLEAR_NAME	_IOW('h', 2, char [16])	/* clear info for specific name */

void usage(char *s)
{
	printf("%s <1|2> [name]\n", s);
	printf("\t1 - clrear data base\n"
	       "\t2 exe_name - clear data for specific name\n");
}

int main(int argc, char *argv[])
{
	int fd;
	int ret;
	int cmd;
	char *name = NULL;
	
	if (argc < 2) {
		usage(argv[0]);
		return 0;
	}

	if (argv[1][0] == '1')
		cmd = CLEAR_DB;
	else if (argv[1][0] == '2')
		cmd = CLEAR_NAME;
	else {
		usage(argv[0]);
		return 0;
	}

	fd = open(device, O_RDWR);
	if (fd < 0) {
		perror("failed");
		return fd;
	}

	if (cmd == CLEAR_NAME)
		name = argv[2];
	ret = ioctl(fd, cmd, name);
	if (ret < 0) {
		perror("failed");
		return ret;
	}

	close(fd);
	return 0;
}
