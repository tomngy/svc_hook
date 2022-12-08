/**
 * @author      : wz 
 * @file        : remote_caller
 * @created     : Wednesday Dec 07, 2022 11:04:11 CST
 */

#include <unistd.h>
#include <stdlib.h>   
#include <sys/syscall.h>
#include <functional>
#include <thread>
#include <signal.h>
//http://aospxref.com/android-13.0.0_r3/s?path=asm/sigcontext.h&project=bionic
#include <asm/sigcontext.h>

#include "remote_caller.h"
#include "logger.h"

#if defined(__i386__)
#include "include/syscalls_x86.h"
const char *const *syscall_table = &kSyscalls_x86[0];
#elif defined(__x86_64__)
#include "include/syscalls_x86_64.h"
const char *const *syscall_table = &kSyscalls_x86_64[0];
#elif defined(__arm__)
#include "include/syscalls_armeabi.h"
const char *const *syscall_table = &kSyscalls_ArmEabi[0];
#elif defined(__aarch64__)
#include "include/syscalls_aarch64.h"
const char *const *syscall_table = &kSyscalls_Aarch64[0];
#endif


void trace_sys_call(int sysno){
    //LOGD("===== handle syscall no %d : %s", sysno, syscall_table[sysno]);
    printf("===== handle syscall no %d : %s\n", sysno, syscall_table[sysno]);
}

#define MAX_SYSCALL_NO 1024
RemoteCaller *g_remote_caller[MAX_SYSCALL_NO] = {0};

RemoteCaller::RemoteCaller(int syscall_no, void *before_hook_func, void *after_hook_func, void *patch_func):
    caller_mutex_(PTHREAD_MUTEX_INITIALIZER),
    caller_cond_(PTHREAD_COND_INITIALIZER),
    callee_mutex_(PTHREAD_MUTEX_INITIALIZER),
    callee_cond_(PTHREAD_COND_INITIALIZER),
    call_result_(0),
    syscall_no_(syscall_no),
    start_loop_(false),
    before_hook_func_((hook_function_t)before_hook_func),
    after_hook_func_((hook_function_t)after_hook_func),
    patch_func_((hook_function_t)patch_func){
    handleSigsys();
    start_remote_thread();
}

RemoteCaller *RemoteCaller::getInstance(int syscall_no){
    if(syscall_no > MAX_SYSCALL_NO-1 || syscall_no < 0){
        LOGE("syscall_no %d error", syscall_no);
        abort();
        return NULL;
    }

    if(g_remote_caller[syscall_no] == NULL){
        g_remote_caller[syscall_no] = new RemoteCaller(syscall_no, NULL, NULL, NULL);
    }

    return g_remote_caller[syscall_no];
}

void RemoteCaller::registerSyscall(int syscall_no, void *before_hook_func, void *after_hook_func, void *patch_func){
    if(syscall_no > MAX_SYSCALL_NO-1 || syscall_no < 0){
        LOGE("syscall_no %d error", syscall_no);
        return;
    }

    if(g_remote_caller[syscall_no] == NULL){
        g_remote_caller[syscall_no] = new RemoteCaller(syscall_no, before_hook_func, after_hook_func, patch_func);
    }
}

bool RemoteCaller::handle_sigsys_ = false;

static void sigsys_handler(int sig, siginfo_t *info, void *secret){
    LOGD("%s : catch siganl %d by caller %p\n", __func__, sig, (void *)info->si_call_addr);
    ucontext_t *ctx = (ucontext_t *)secret;
    struct sigcontext *sigctx = reinterpret_cast<struct sigcontext *>(&ctx->uc_mcontext);
    bool is_handle_syscall = false;
#if defined(__i386__)
    //int 80 = [ cd 50 ]
    uint8_t *insn = (((uint8_t *)info->si_call_addr) - 2);
    is_handle_syscall = (insn[0] == 0xcd) && (insn[1] == 0x50);
    int sysno = sigctx->eax;
    unsigned long *presult = (unsigned long *)&sigctx->eax;
#elif defined(__x86_64__)
    //int 80 = [ cd 50 ]
    uint8_t *insn = (((uint8_t *)info->si_call_addr) - 2);
    is_handle_syscall = (insn[0] == 0xcd) && (insn[1] == 0x50);
    int sysno = sigctx->rax;
    unsigned long *presult = (unsigned long *)&sigctx->rax;
#elif defined(__arm__)
    is_handle_syscall = *(((uint32_t *)info->si_call_addr) - 1) == 0xef000000; //00 00 00 ef  svc     #0
    int sysno = sigctx->arm_r7;
    unsigned long *presult = (unsigned long *)&sigctx->arm_r0;
#elif defined(__aarch64__)
    is_handle_syscall = *(((uint32_t *)info->si_call_addr) - 1) == 0xd4000001; //01 00 00 d4  svc     #0
    int sysno = sigctx->regs[8];
    unsigned long *presult = (unsigned long *)&sigctx->regs[0];
#else
    LOGE("unsupport arch");
    exit(0);
#endif
    if(is_handle_syscall){
        long ret = RemoteCaller::getInstance(sysno)->remote_syscall(sigctx);
        *presult = ret;
    }else{
        LOGD(">>>>> handle signal not caused by ebpf");
    }
}

void RemoteCaller::handleSigsys(){
    if(!RemoteCaller::handle_sigsys_){
        LOGD("register SIGSYS start");
        struct sigaction act;
        struct sigaction old_act;
        sigemptyset(&act.sa_mask);
        act.sa_flags = SA_NODEFER | SA_ONSTACK  | SA_SIGINFO;
        act.sa_sigaction = sigsys_handler;
        sigaction(SIGSYS, &act, &old_act);
        RemoteCaller::handle_sigsys_ = true;
        LOGD("register SIGSYS end");
    }
}

unsigned long RemoteCaller::get_syscall_param(sigcontext* sigctx, int index){
    if(index < 0 || index >= 6) return 0;
    unsigned long *regs = NULL;
    unsigned long *sp = NULL;
#if defined(__i386__)
    sp = (unsigned long *)sigctx->esp;
    switch(index){
        case 0:
            return sigctx->eax;
        case 1:
            return sigctx->eax;
        case 2:
            return sigctx->eax;
        case 3:
            return sigctx->esp;
        case 4:
            return sp[1];
        case 5:
            return sp[2];
        default:
            return 0;
    }
#elif defined(__x86_64__)
    //
    sp = (unsigned long *)sigctx->rsp;
    switch(index){
        case 0:
            return sigctx->rdi;
        case 1:
            return sigctx->rsi;
        case 2:
            return sigctx->rdx;
        case 3:
            //if is syscallno == NR_syscall
            //return sigctx->r10;
            return sigctx->rcx;
        case 4:
            return sigctx->r8;
        case 5:
            return sigctx->r9;
        default:
            return 0;
    }
#elif defined(__arm__)
    regs = (unsigned long *)&sigctx->arm_r0;
    sp = (unsigned long *)sigctx->arm_sp;
    if(index <= 3) {
        //r0 - r3
        return regs[index];
    }else{
        //stack
        return sp[index-3];
    }
#elif defined(__aarch64__)
    regs = (unsigned long *)&(sigctx->regs[0]);
    sp = (unsigned long *)sigctx->sp;
    if(index <= 7) {
        //x0 - x7
        return regs[index];
    }else{
        //stack
        return sp[index-3];
    }
#else
    LOGE("unsupport arch");
    exit(0);
#endif
}

void *RemoteCaller::remote_call_thread_function(void *args_ptr){
    pthread_cond_signal(&caller_cond_);
    while(start_loop_){
        pthread_mutex_lock(&callee_mutex_);
        LOGD("## RemoteCaller wait call");
        pthread_cond_wait(&callee_cond_, &callee_mutex_);
        
        LOGD("## RemoteCaller wait call");
#if 1
        unsigned long param0 = get_syscall_param(call_args_, 0);
        unsigned long param1 = get_syscall_param(call_args_, 1);
        unsigned long param2 = get_syscall_param(call_args_, 2);
        unsigned long param3 = get_syscall_param(call_args_, 3);
        unsigned long param4 = get_syscall_param(call_args_, 4);
        //unsigned long param5 = get_syscall_param(call_args_, 5);
        //do something before hook
        if(before_hook_func_){
            before_hook_func_(param0, param1, param2, param3, param4);
        }
        call_result_ = syscall(syscall_no_, param0, param1, param2, param3, param4);

	trace_sys_call(syscall_no_);
        //do something after hook
        if(after_hook_func_){
            after_hook_func_(param0, param1, param2, param3, param4);
        }

        //patch result or do something after hook
        if(patch_func_){
            call_result_ = patch_func_(param0, param1, param2, param3, param4);
        }
#else
        switch(syscall_no_){
            case __NR_openat:
                call_result_ = syscall(syscall_no_,
                                       get_syscall_param(call_args_, 0),
                                       get_syscall_param(call_args_, 1),
                                       get_syscall_param(call_args_, 2),
                                       get_syscall_param(call_args_, 3),
                                       get_syscall_param(call_args_, 4),
                                       get_syscall_param(call_args_, 5)
                                       );
                break;
            default:
                LOGE("unsupport syscall %d, add call function type\n", syscall_no_);
                call_result_ = -1;
                break;
        }
#endif
        LOGD("## RemoteCaller call_result_ is %ld", call_result_);
        pthread_mutex_unlock(&callee_mutex_);
        LOGD("## RemoteCaller wake call thread");
        pthread_cond_signal(&caller_cond_);
    }
    return NULL;
}

void RemoteCaller::start_remote_thread(){
    if(!start_loop_){
        start_loop_ = true;
        LOGD("start remote thread for syscall no %d", syscall_no_);
        pthread_mutex_lock(&caller_mutex_);
        std::thread td(std::bind(&RemoteCaller::remote_call_thread_function, this, (void *)&call_args_));
        td.detach();
        //这里要保证线程逻辑起来，所以必须要wait
        pthread_cond_wait(&caller_cond_, &caller_mutex_);
        pthread_mutex_unlock(&caller_mutex_);
        LOGD("start remote thread for syscall no %d finished", syscall_no_);
    }
}

void RemoteCaller::stop_remote_thread(){
    start_loop_ = false;
}

//线程中内存是共享的，所以remote call转换传递参数给当前线程，并等待结果
long RemoteCaller::remote_syscall(sigcontext *sigctx){
    //这里控制所有的syscall排队
    LOGD("locked exec remote_syscall");
    pthread_mutex_lock(&caller_mutex_);
    call_args_ = sigctx;
    //如果一个系统调用一个线程的情况，这里不需要复制，这里是为了写通用的情况
    //signal 唤醒线程，等待
    LOGD("wake up remote thread");
    pthread_cond_signal(&callee_cond_);

    //强制让调用进程等待
    LOGD("wait remote thread...");
    pthread_cond_wait(&caller_cond_, &caller_mutex_);

    //wait signal
    long ret = call_result_;
    pthread_mutex_unlock(&caller_mutex_);
    LOGD("unlocked exec remote_syscall");
    return ret;
}
