// /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.7.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers
// /System/Library/Extensions/System.kext/PlugIns

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <kern/locks.h>
#include <sys/malloc.h>
#include <libkern/OSMalloc.h>
#include <sys/sysctl.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <kern/thread.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <kern/task.h>
#include <kern/sched_prim.h>
#include <kern/clock.h>
#include <mach/clock_types.h>
#include <kern/thread_call.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>

/* These symbols are exported by OS X as unsupported, but are not defined in XCode (kernel framework) headers */
extern int  tsleep(void *chan, int pri, const char *wmesg, int timo);
extern int  msleep1(void *chan, lck_mtx_t *mtx, int pri, const char *wmesg, u_int64_t timo);
extern int  sleep(void *chan, int pri);
extern void delay(int usec);
extern int  hz;

static uint64_t
timeval_to_absolute_time(struct timeval* tvp)
{
    return mach_absolute_time() + tvtoabstime(tvp);
}

#define NTHREADS 4

static lck_grp_t* lock_group = NULL;
static lck_spin_t* spinlock = NULL;
static lck_mtx_t* sysctl_mutex = NULL;
static OSMallocTag mtag = NULL;
static boolean_t sysctl_registered = FALSE;
static thread_t kthreads[NTHREADS];
static boolean_t stopping = FALSE;
static void kthread_main(void* parameter, wait_result_t wr);

/* callout data */
static thread_call_t callout = NULL;
static lck_spin_t* co_lock = NULL;
boolean_t co_scheduled = FALSE;
boolean_t co_cancel = FALSE;
boolean_t co_cancel_ack = FALSE;
static void callout_drain(thread_call_t call);
static boolean_t callout_start(thread_call_t call, thread_call_param_t param1);
static void callout_func(thread_call_param_t param0, thread_call_param_t param1);

#define XS_MAXSIZE 256
static int32_t  mytest_sysctl_x = 1;
static uint64_t mytest_sysctl_y = 2;
static char     mytest_sysctl_s[100] = "initial_s";
static char     mytest_sysctl_sp[100] = "initial_sp";
static uint8_t  mytest_sysctl_xs[XS_MAXSIZE];
size_t          mytest_sysctl_xs_len = 16;
static int mytest_sysctl_proc_sp SYSCTL_HANDLER_ARGS;
static int mytest_sysctl_proc_xs SYSCTL_HANDLER_ARGS;

static d_open_t mydev_open;
static d_close_t mydev_close;
static d_read_t mydev_read;
static d_write_t mydev_write;
static d_ioctl_t mydev_ioctl;
static struct cdevsw mydev_cdevsw = 
{
    .d_open = mydev_open,
    .d_close = mydev_close,
    .d_read = mydev_read,
    .d_write = mydev_write,
    .d_ioctl = mydev_ioctl,
    .d_stop = eno_stop,
    .d_reset = eno_reset,
    .d_ttys = NULL,
    .d_select = eno_select,
    .d_mmap = eno_mmap,
    .d_strategy = eno_strat,
    .d_type = 0,
};
static int cdev_major = -1;
static void* cdev_handle = NULL;
static lck_rw_t* mydev_rwlock = NULL;
static char* mydev_buf = NULL;
unsigned long mydev_buf_size = 0;

static void release_all();
static void dump8(const char* header, void* addr, int count);

/* 
 * CTLFLAG_LOCKED anywhere on the path to sysctl element (including its parent elements) will cause kernel_flock 
 * being pre-acquired for the duration of the call to oid_handler routine. If this flag is not set, the handler
 * should do its own locking. 
 *
 * CTLFLAG_ANYBODY allows any user change the element, rather than root alone.
 */
SYSCTL_NODE    (_debug, OID_AUTO, mytest, CTLFLAG_RD | CTLFLAG_KERN, NULL, "mytest data directory");
SYSCTL_UINT    (_debug_mytest, OID_AUTO, x, CTLFLAG_RW | CTLFLAG_KERN | CTLFLAG_LOCKED, &mytest_sysctl_x, 0, "explain x");
SYSCTL_QUAD    (_debug_mytest, OID_AUTO, y, CTLFLAG_RW | CTLFLAG_KERN | CTLFLAG_LOCKED, &mytest_sysctl_y, "explain y");
SYSCTL_PROC    (_debug_mytest, OID_AUTO, xs, CTLTYPE_OPAQUE | CTLFLAG_ANYBODY | CTLFLAG_KERN | CTLFLAG_RW,
                     &mytest_sysctl_xs,         // location
                     XS_MAXSIZE,                // maximum allowed size
                     mytest_sysctl_proc_xs,     // handler procedure
                     "S,xs",                    // data format ("A": string, "I" = int, "IU" = uint, "L" = long, "Q" = quad, "S,structname" = struct)
                     "explain xs");

SYSCTL_NODE    (_debug_mytest, OID_AUTO, sub, CTLFLAG_RD | CTLFLAG_KERN, NULL, "mytest data subdirectory");
SYSCTL_STRING  (_debug_mytest_sub, OID_AUTO, s, CTLFLAG_RW | CTLFLAG_KERN | CTLFLAG_LOCKED, mytest_sysctl_s, sizeof(mytest_sysctl_s), "explain s");
SYSCTL_PROC    (_debug_mytest_sub, OID_AUTO, sp, CTLTYPE_STRING | CTLFLAG_ANYBODY | CTLFLAG_KERN | CTLFLAG_RW,
                     &mytest_sysctl_sp,         // location
                     100,                       // maximum allowed size
                     mytest_sysctl_proc_sp,     // handler procedure
                     "A",                       // data format ("A": string, "I" = int, "IU" = uint, "L" = long, "Q" = quad, "S,structname" = struct)
                     "explain sp");

// typedef enum
// {
//     MY_MODE_NONE = 0,                   /* unassigned, usually for saved_mode only */
//     MY_MODE_REALTIME,                   /* time constraints supplied */
//     MY_MODE_FIXED,                      /* use fixed priorities, no decay */
//     MY_MODE_TIMESHARE,                  /* use timesharing algorithm */
//     MY_MODE_FAIRSHARE                   /* use fair-share scheduling */     
// } 
// my_enum_t;

// static my_enum_t myvar_enum;
// static short myvar_short;
// static int myvar_int;
// static long myvar_long;

kern_return_t mytest_a_start(kmod_info_t * ki, void *d)
{
    lck_grp_attr_t* grp_attr;
    lck_attr_t* lock_attr;
    kern_return_t kr;
    void* p1 = NULL;
    // void* p2 = NULL;
    int k;

    printf("MyTestA starting.\n");

    // printf("sizeof enum: %d\n", (int) sizeof(myvar_enum));         // 4
    // printf("sizeof short: %d\n", (int) sizeof(myvar_short));       // 2
    // printf("sizeof int: %d\n", (int) sizeof(myvar_int));           // 4
    // printf("sizeof long: %d\n", (int) sizeof(myvar_long));         // 8
    // printf("sizeof uintptr_t: %d\n", (int) sizeof(uintptr_t));     // 8

    for (k = 0;  k < NTHREADS;  k++)
        kthreads[k] = NULL;

    for (k = 0;  k < XS_MAXSIZE;  k++)
        mytest_sysctl_xs[k] = (uint8_t) k;

    mtag = OSMalloc_Tagalloc("mytesta OSMalloc tag", OSMT_DEFAULT);
    if (mtag == NULL)
    {
        printf("MyTestA: Failed to allocate OSMalloc tag\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }

    grp_attr = lck_grp_attr_alloc_init();
    if (grp_attr != NULL)
    {
        lock_group = lck_grp_alloc_init("mytesta lock group", grp_attr);
        lck_grp_attr_free(grp_attr);
    }
    if (lock_group == NULL)
    {
        printf("MyTestA: Failed to allocate locking group\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }

    lock_attr = lck_attr_alloc_init();
    if (lock_attr != NULL)
    {
        spinlock = lck_spin_alloc_init(lock_group, lock_attr);
        lck_attr_free(lock_attr);
    }
    if (spinlock == NULL)
    {
        printf("MyTestA: Failed to allocate spinlock\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }

    lock_attr = lck_attr_alloc_init();
    if (lock_attr != NULL)
    {
        sysctl_mutex = lck_mtx_alloc_init(lock_group, lock_attr);
        lck_attr_free(lock_attr);
    }
    if (sysctl_mutex == NULL)
    {
        printf("MyTestA: Failed to allocate mutex\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }

    lock_attr = lck_attr_alloc_init();
    if (lock_attr != NULL)
    {
        co_lock = lck_spin_alloc_init(lock_group, lock_attr);
        lck_attr_free(lock_attr);
    }
    if (co_lock == NULL)
    {
        printf("MyTestA: Failed to allocate spinlock\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }

    lock_attr = lck_attr_alloc_init();
    if (lock_attr != NULL)
    {
        mydev_rwlock = lck_rw_alloc_init(lock_group, lock_attr);
        lck_attr_free(lock_attr);
    }
    if (mydev_rwlock == NULL)
    {
        printf("MyTestA: Failed to allocate rwlock\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }

    callout = thread_call_allocate(callout_func, & callout);
    if (callout == NULL)
    {
        printf("MyTestA: Failed to allocate callout\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }

    printf("MyTestA: MyTestA: Trying malloc #1.\n");
    p1 = OSMalloc(10, mtag);
    if (p1 != NULL)
        OSFree(p1, 10, mtag);

    printf("MyTestA: Trying lock/unlock.\n");
    lck_spin_lock(spinlock);
    lck_spin_unlock(spinlock);

    printf("MyTestA: Regstering sysctl.\n");
    sysctl_register_oid(&sysctl__debug_mytest);
    sysctl_register_oid(&sysctl__debug_mytest_x);
    sysctl_register_oid(&sysctl__debug_mytest_y);
    sysctl_register_oid(&sysctl__debug_mytest_xs);
    sysctl_register_oid(&sysctl__debug_mytest_sub);
    sysctl_register_oid(&sysctl__debug_mytest_sub_s);
    sysctl_register_oid(&sysctl__debug_mytest_sub_sp);
    sysctl_registered = TRUE;

    printf("MyTestA: Starting callout.\n");
    if (! callout_start(callout, "abc"))
    {
        printf("MyTestA: Failed to start callout\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }

    printf("MyTestA: Starting threads.\n");
    for (k = 0;  k < NTHREADS;  k++)
    {
        kr = kernel_thread_start(kthread_main, (void*) (long) k, & kthreads[k]);
        if (kr != KERN_SUCCESS)
            printf("MyTestA: Failed to start thread.\n");

        // if (k == 0)
        // {
        //     thread_t td = kthreads[0];
        //     thread_precedence_policy_data_t precedinfo;
        // 
        //     dump8("before setpri", td, 20);
        // 
        //     precedinfo.importance = 10;
        //     thread_policy_set(td, THREAD_PRECEDENCE_POLICY, (thread_policy_t) &precedinfo, THREAD_PRECEDENCE_POLICY_COUNT);
        //     dump8("after setpri +10", td, 20);
        // 
        //     precedinfo.importance = -5;
        //     thread_policy_set(td, THREAD_PRECEDENCE_POLICY, (thread_policy_t) &precedinfo, THREAD_PRECEDENCE_POLICY_COUNT);
        //     dump8("after setpri -5", td, 20);
        // }
    }

    printf("MyTestA: Creating device.\n");
    cdev_major = cdevsw_add(-24, &mydev_cdevsw);
    if (cdev_major < 0)
    {
        printf("MyTestA: Failed to create device\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }
    cdev_handle = devfs_make_node(makedev(cdev_major, 0), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0600, "mydev");
    if (cdev_handle == NULL)
    {
        printf("MyTestA: Failed to register device\n");
        release_all();
        return KERN_RESOURCE_SHORTAGE;
    }

    printf("MyTestA has started.\n");
    return KERN_SUCCESS;
}

static void release_all()
{
    int k;

    printf("MyTestA: Unregistering device.\n");
    if (cdev_handle != NULL)
    {
        devfs_remove(cdev_handle);
        cdev_handle = NULL;
    }

    if (cdev_major >= 0)
    {
        cdevsw_remove(cdev_major, &mydev_cdevsw);
        cdev_major = -1;
    }

    if (mydev_rwlock != NULL)
    {
        lck_rw_free(mydev_rwlock, lock_group);
        mydev_rwlock = NULL;
    }

    if (mydev_buf != NULL)
    {
        _FREE(mydev_buf, M_TEMP);
        mydev_buf = NULL;
    }
    mydev_buf_size = 0;

    stopping = TRUE;

    printf("MyTestA: Stopping threads.\n");
    for (k = 0;  k < NTHREADS;  k++)
    {
        if (kthreads[k] != NULL)
            wakeup(&kthreads[k]);
    }
    for (k = 0;  k < NTHREADS;  k++)
    {
        if (kthreads[k] != NULL)
        {
            /* 
             * OS X does not export a good primitve to wait for thread completion.
             * The only thing we can do is to poll.
             */
            for (;;)
            {
                // thread_basic_info_data_t basic_info;
                // mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
                // if (KERN_TERMINATED == thread_info(kthreads[k], THREAD_BASIC_INFO, (thread_info_t) &basic_info, & count))
                //     break;
                thread_precedence_policy_data_t precedinfo;
                precedinfo.importance = 0;
                if (KERN_TERMINATED == thread_policy_set(kthreads[k], THREAD_PRECEDENCE_POLICY, (thread_policy_t) &precedinfo, THREAD_PRECEDENCE_POLICY_COUNT))
                    break;
                tsleep(NULL, PWAIT, "threadexit", max(1, hz / 1000));
            }
            thread_deallocate(kthreads[k]);
            kthreads[k] = NULL;
        }
    }
    printf("MyTestA: Stopped threads.\n");

    if (sysctl_registered)
    {
        sysctl_unregister_oid(&sysctl__debug_mytest);
        sysctl_unregister_oid(&sysctl__debug_mytest_x);
        sysctl_unregister_oid(&sysctl__debug_mytest_y);
        sysctl_unregister_oid(&sysctl__debug_mytest_xs);
        sysctl_unregister_oid(&sysctl__debug_mytest_sub);
        sysctl_unregister_oid(&sysctl__debug_mytest_sub_s);
        sysctl_unregister_oid(&sysctl__debug_mytest_sub_sp);
        sysctl_registered = FALSE;
    }

    printf("MyTestA: Stopping callout.\n");
    if (callout != NULL)
    {
        callout_drain(callout);
        thread_call_free(callout);
    }
    printf("MyTestA: Stopped callout.\n");

    if (co_lock != NULL)
    {
        lck_spin_free(co_lock, lock_group);
        co_lock = NULL;
    }

    if (sysctl_mutex != NULL)
    {
        lck_mtx_free(sysctl_mutex, lock_group);
        sysctl_mutex = NULL;
    }

    if (spinlock != NULL)
    {
        lck_spin_free(spinlock, lock_group);
        spinlock = NULL;
    }

    if (lock_group != NULL)
    {
        lck_grp_free(lock_group);
        lock_group = NULL;
    }

    if (mtag != NULL)
    {
        OSMalloc_Tagfree(mtag);
        mtag = NULL;
    }

    /* give callout thread some time to really complete, see the comment in callout_func */
    tsleep(NULL, PWAIT, "cleanup", max(1, hz / 10));
}

kern_return_t mytest_a_stop(kmod_info_t *ki, void *d)
{
    printf("MyTestA is stopping.\n");
    release_all();
    printf("MyTestA has stopped.\n");
    return KERN_SUCCESS;
}


static int mytest_sysctl_proc_sp SYSCTL_HANDLER_ARGS  // (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req)
{
    // arg1 = "location", as specified in SYSCTL_PROC
    // arg2 = "maximum allowed size", as specified in SYSCTL_PROC
    // error = SYSCTL_OUT(req, p, size)  -- copyout from kernel-space block(p/size) to caller's buffer
    // error = SYSCTL_IN(req, p, size)  -- copyin from caller's buffer into kernel-space block(p/size), result size is in req->newlen
    int error;
    lck_mtx_lock(sysctl_mutex);
    error = sysctl_handle_string(oidp, arg1, arg2, req);
    if (error)
    {
        // failed request
    }
    else if (req->newptr)
    {
        // successful write request
        printf("TestA: have set value of %s to %s\n", oidp->oid_name, (char*) arg1);
    }
    else
    {
        // successful read request
    }
    lck_mtx_unlock(sysctl_mutex);
    return error;
}

static int mytest_sysctl_proc_xs SYSCTL_HANDLER_ARGS  // (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req)
{
    // arg1 = "location", as specified in SYSCTL_PROC
    // arg2 = "maximum allowed size", as specified in SYSCTL_PROC
    // error = SYSCTL_OUT(req, p, size)  -- copyout from kernel-space block(p/size) to caller's buffer
    // error = SYSCTL_IN(req, p, size)  -- copyin from caller's buffer into kernel-space block(p/size), result size is in req->newlen
    int error;
    lck_mtx_lock(sysctl_mutex);
    printf("MyTestA: sysctl copyout %s, size: %d\n", oidp->oid_name, (int) mytest_sysctl_xs_len);
    error = SYSCTL_OUT(req, mytest_sysctl_xs, mytest_sysctl_xs_len);
    if (error == 0 && req->newptr)
    {
        error = SYSCTL_IN(req, mytest_sysctl_xs, XS_MAXSIZE);
        if (error == 0)
            mytest_sysctl_xs_len = req->newlen;
        printf("MyTestA: sysctl have set %s, newsize: %d\n", oidp->oid_name, (int) mytest_sysctl_xs_len);
    }
    lck_mtx_unlock(sysctl_mutex);
    return error;
}

static void kthread_main(void* parameter, __unused wait_result_t wr)
{
    int tn = (int) (long) parameter;
    unsigned long count = 0;

    printf("MyTestA: kthread: %d\n", tn);

    for (;;)
    {
        tsleep(&kthreads[tn], PZERO, "loop sleep", hz * 1);

        if (stopping)
        {
            printf("MyTestA: kthread %d: exiting\n", tn);
            thread_terminate(current_thread());
        }

        if (0 == (count++ % 10))
            printf("MyTestA: kthread %d: loop\n", tn);
    }
}

static void 
callout_func(thread_call_param_t param0, thread_call_param_t param1)
{
    thread_call_t call = * (thread_call_t*) param0;
    if (! co_cancel)
    {
        /* do some processing */
        printf("MyTestA: callout: %s\n", (char*) param1);
    }

    lck_spin_lock(co_lock);
    if (co_cancel)
    {
        co_scheduled = FALSE;
        co_cancel_ack = TRUE;
    }
    else
    {
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        thread_call_enter1_delayed(call, param1, timeval_to_absolute_time(&tv));
        co_scheduled = TRUE;
        co_cancel_ack = FALSE;
    }
    lck_spin_unlock(co_lock);
    /* 
     * It may take the thread some time to exit out of callout_func on cancel_ack path.
     * This is why kext must wait some time before finally unloading.
     * We have to do this because OS X does not export thread_call_cancel_wait.
     */
}

/*
 * Can be called while holding a spinlock.
 * May not be called while call is already active.
 */
static boolean_t 
callout_start(thread_call_t call, thread_call_param_t param1)
{
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;

    lck_spin_lock(co_lock);
    if (co_cancel)
    {
        lck_spin_unlock(co_lock);
        return FALSE;
    }

    thread_call_enter1_delayed(call, param1, timeval_to_absolute_time(&tv));
    co_scheduled = TRUE;
    co_cancel_ack = FALSE;

    lck_spin_unlock(co_lock);
    return TRUE;
}

/*
 * Can be called while holding a spinlock.
 *
 * Must not be called from an interrupt, otherwise may preempt timer processing thread
 * and it never gets a chance to set co_cancel_ack.
 */
static void 
callout_drain(thread_call_t call)
{
    for (int ntry = 0; ;  ntry++)
    {
        lck_spin_lock(co_lock);

        /*
         * Note that thread_call_cancel does not wait for timer routine to complete,
         * so there is no danger of deadlocking against timer routine that also acquires co_lock.
         */
        if (thread_call_cancel(call))
        {
            /* removed from queue */
            co_scheduled = FALSE;
            co_cancel = FALSE;
            co_cancel_ack = TRUE;
            lck_spin_unlock(co_lock);
            return;
        }

        /* currently executing or not queued */
        if (! co_scheduled)
        {
            co_cancel = FALSE;
            co_cancel_ack = FALSE;
            lck_spin_unlock(co_lock);
            return;
        }

        if (co_cancel_ack)
        {
            co_cancel = FALSE;
            lck_spin_unlock(co_lock);
            return;
        }

        co_cancel = TRUE;
        lck_spin_unlock(co_lock);

        if (ntry++ > 10 && preemption_enabled())
        {
            tsleep(call, PVFS, "callout_drain", 1);
        }
        else
        {
            /* will spin or sleep: will spin if cannot sleep (too short for sleep, 
               interrupts are disabled or preemption is disabled) */
            delay(10);   /* usec */
        }
    }
}

static int mydev_open(dev_t dev, int flags, int devtype, struct proc *p)
{
    return 0;
}

static int mydev_close(dev_t dev, int flags, int devtype, struct proc *p)
{
    return 0;
}

static int mydev_read(dev_t dev, struct uio* uio, int ioflag)
{
    int error = 0;
    ssize_t amt;

    lck_rw_lock_shared(mydev_rwlock);

    amt = (ssize_t) MIN(uio_resid(uio), (ssize_t) mydev_buf_size - (ssize_t) uio_offset(uio));
    if (amt < 0)  amt = 0;

    /* uiomove decrements uio_resid and advances uio_offset */
    if (amt)
        error = uiomove(mydev_buf + uio_offset(uio), (int) amt, uio);

    lck_rw_unlock_shared(mydev_rwlock);

    return error;
}

static int mydev_write(dev_t dev, struct uio* uio, int ioflag)
{
    /* we always append, so ignore uio->uio_offset */
    unsigned long offset = mydev_buf_size;
    ssize_t amt;
    char* p;
    int error = 0;

    lck_rw_lock_exclusive(mydev_rwlock);

    if (mydev_buf == NULL)
        p = _MALLOC(uio_resid(uio), M_TEMP, M_WAITOK);
    else
        p = _REALLOC(mydev_buf, uio_resid(uio) + mydev_buf_size, M_TEMP, M_WAITOK);

    if (p == NULL)
    {
        lck_rw_unlock_exclusive(mydev_rwlock);
        return ENOMEM;
    }

    mydev_buf = p;
    amt = uio_resid(uio);
    error = uiomove(p + offset, (int) amt, uio);
    if (error == 0)
        mydev_buf_size += amt;

    lck_rw_unlock_exclusive(mydev_rwlock);

    return error;
}

static int mydev_ioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
    return ENXIO;
}

static void dump8(const char* header, void* addr, int count)
{
    uint64_t* p = (uint64_t*) addr;
    int k;
    printf("%s\n", header);
    for (k = 0;  k < count;  k++)
        printf("    [%02d]: %08X %08X\n", k, (uint32_t) ((p[k] >> 32) & 0xFFFFFFFF), (uint32_t) (p[k] & 0xFFFFFFFF));
}

/*************************************************************************************
*  OS X does not export _REALLOC                                                     *
*************************************************************************************/

struct _mhead {
    size_t  mlen;
    char    dat[0];
};

void *
_REALLOC(
    void    *addr,
    size_t  size,
    int     type,
    int     flags)
{
    struct _mhead   *hdr;
    void        *newaddr;
    size_t      alloc;

    /* realloc(NULL, ...) is equivalent to malloc(...) */
    if (addr == NULL)
        return (_MALLOC(size, type, flags));

    /* Allocate a new, bigger (or smaller) block */
    if ((newaddr = _MALLOC(size, type, flags)) == NULL)
        return (NULL);

    hdr = addr;
    --hdr;
    alloc = hdr->mlen - sizeof (*hdr);

    /* Copy over original contents */
    bcopy(addr, newaddr, MIN(size, alloc));
    _FREE(addr, type);

    return (newaddr);
}
