/**
 * @author      : wz 
 * @file        : test
 * @created     : Tuesday Jul 05, 2022 20:29:13 CST
 */
#include <stdio.h>
#include <unistd.h>   
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include "svc_hook.h"

int before_openat(int dirfd, const char *pathname, int flags){
    printf("%s %s\n", __func__, pathname);
    return -1;
}

int after_openat(int dirfd, const char *pathname, int flags){
    printf("%s %s\n", __func__, pathname);
    return -1;
}

int main(int argc, char **argv){
    svc_hook(__NR_openat, NULL, (void *)&after_openat, NULL);
    svc_hook(__NR_read, NULL, NULL, NULL);
    svc_hook(__NR_pread64, NULL, NULL, NULL);

    int fd = open("/proc/self/maps", 0);
    printf("open fd is %d\n", fd);
    if(fd > 0){
        char buf[1024] = {0};
        ssize_t sz = read(fd, buf, 16);
        printf("read buf : %s\n", buf);
    }

    getchar();
    return 0;
}
