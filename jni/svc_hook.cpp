/**
 * @author      : wz
 * @file        : svc_hook
 * @created     : Thursday Dec 01, 2022 16:39:34 CST
 */
#define _GNU_SOURCE 1
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <unistd.h>     
#include <sys/syscall.h>
#include <sys/types.h> 
#include <sys/stat.h>
#include <fcntl.h>     
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>

#include "svc_hook.h"
#include "remote_caller.h"
#include "logger.h"

int svc_register_hook(int signo){
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, signo, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        LOGE("prctl(NO_NEW_PRIVS)");
        goto failed;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        LOGE("prctl(SECCOMP)");
        goto failed;
    }
    return 0;

failed:
    if (errno == EINVAL)
        LOGE("SECCOMP_FILTER is not available. :(n\n");
    return -1;
}

int svc_hook(int sysno, void *before_hook_func, void *after_hook_func, void *patch_func){
    RemoteCaller::registerSyscall(sysno, before_hook_func, after_hook_func, patch_func);
    return svc_register_hook(sysno);
}