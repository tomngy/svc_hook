/**
 * @author      : wz 
 * @file        : svc_hook
 * @created     : Thursday Dec 01, 2022 16:36:06 CST
 */

#ifndef SVC_HOOK_H
#define SVC_HOOK_H

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

int svc_hook(int sysno, void *before_hook_func, void *after_hook_func, void *patch_func);

#ifdef __cplusplus
}
#endif

#endif /* end of include guard SVC_HOOK_H */

