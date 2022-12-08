/**
 * @author      : wz 
 * @file        : remote_caller
 * @created     : Wednesday Dec 07, 2022 11:04:08 CST
 */

#ifndef REMOTE_CALLER_H
#define REMOTE_CALLER_H

#include <pthread.h>

typedef long (*hook_function_t)(unsigned long,unsigned long,unsigned long,unsigned long,unsigned long);

class RemoteCaller{
    public:        
        static void registerSyscall(int syscall_no, void *before_hook_func, void *after_hook_func, void *patch_func_ = NULL);
        static RemoteCaller *getInstance(int syscall_no);
        long remote_syscall(sigcontext *sigctx);
    
    protected:
        RemoteCaller(int syscall_no, void *before_hook_func, void *after_hook_func, void *patch_func_);

        void *remote_call_thread_function(void *args);
        void start_remote_thread();
        void stop_remote_thread();
        unsigned long get_syscall_param(sigcontext* sigctx, int index);

        static void handleSigsys();
    private:
        pthread_mutex_t caller_mutex_;
        pthread_cond_t  caller_cond_;
        pthread_mutex_t callee_mutex_;
        pthread_cond_t  callee_cond_;
        long call_result_;
        int syscall_no_;
        bool start_loop_;
        sigcontext *call_args_;
        hook_function_t before_hook_func_;
        hook_function_t after_hook_func_;
        hook_function_t patch_func_;
        static bool handle_sigsys_;
};


#endif /* end of include guard REMOTE_CALLER_H */

