/* This task handles the interface between the kernel and user-level servers.
 * System services can be accessed by doing a system call. System calls are
 * transformed into request messages, which are handled by this task. By
 * convention, a sys_call() is transformed in a SYS_CALL request message that
 * is handled in a function named do_call().
 *
 * A private call vector is used to map all system calls to the functions that
 * handle them. The actual handler functions are contained in separate files
 * to keep this file clean. The call vector is used in the system task's main
 * loop to handle all incoming requests.
 *
 * In addition to the main sys_task() entry point, which starts the main loop,
 * there are several other minor entry points:
 *   get_priv:		assign privilege structure to user or system process
 *   set_sendto_bit:	allow a process to send messages to a new target
 *   unset_sendto_bit:	disallow a process from sending messages to a target
 *   fill_sendto_mask:	fill the target mask of a given process
 *   send_sig:		send a signal directly to a system process
 *   cause_sig:		take action to cause a signal to occur via a signal mgr
 *   sig_delay_done:	tell PM that a process is not sending
 *   send_diag_sig:	send a diagnostics signal to interested processes
 *   get_randomness:	accumulate randomness in a buffer
 *   clear_endpoint:	remove a process' ability to send and receive messages
 *   sched_proc:	schedule a process
 *
 * Changes:
*    Nov 22, 2009   get_priv supports static priv ids (Cristiano Giuffrida)
 *   Aug 04, 2005   check if system call is allowed  (Jorrit N. Herder)
 *   Jul 20, 2005   send signal to services with message  (Jorrit N. Herder)
 *   Jan 15, 2005   new, generalized virtual copy function  (Jorrit N. Herder)
 *   Oct 10, 2004   dispatch system calls from call vector  (Jorrit N. Herder)
 *   Sep 30, 2004   source code documentation updated  (Jorrit N. Herder)
 */

#include "kernel/system.h"
#include "kernel/vm.h"
#include "kernel/clock.h"
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <minix/endpoint.h>
#include <minix/safecopies.h>

/* Declaration of the call vector that defines the mapping of system calls
 * to handler functions. The vector is initialized in sys_init() with map(),
 * which makes sure the system call numbers are ok. No space is allocated,
 * because the dummy is declared extern. If an illegal call is given, the
 * array size will be negative and this won't compile.
 */
static int (*call_vec[NR_SYS_CALLS])(struct proc * caller, message *m_ptr);

#define map(call_nr, handler) 					\
    {	int call_index = call_nr-KERNEL_CALL; 				\
    	assert(call_index >= 0 && call_index < NR_SYS_CALLS);			\
    call_vec[call_index] = (handler)  ; }

static void handle_user_copy_error(struct proc *caller)
{
    printf("WARNING wrong user pointer 0x%08x from process %s / %d\n",
           caller->p_delivermsg_vir,
           caller->p_name,
           caller->p_endpoint);
    cause_sig(proc_nr(caller), SIGSEGV);
}

static void reply_to_caller(struct proc *caller, message *msg, int result)
{
    msg->m_source = SYSTEM;
    msg->m_type = result;

#if DEBUG_IPC_HOOK
    hook_ipc_msgkresult(msg, caller);
#endif

    if (copy_msg_to_user(msg, (message *)caller->p_delivermsg_vir) != 0) {
        handle_user_copy_error(caller);
    }
}

static void save_kernel_call_for_vm(struct proc *caller, const message *msg)
{
    assert(RTS_ISSET(caller, RTS_VMREQUEST));
    assert(caller->p_vmrequest.type == VMSTYPE_KERNELCALL);
    caller->p_vmrequest.saved.reqmsg = *msg;
    caller->p_misc_flags |= MF_KCALL_RESUME;
}

static void complete_kernel_call(struct proc *caller, message *msg, int result)
{
    caller->p_vmrequest.saved.reqmsg.m_source = NONE;

    if (result != EDONTREPLY) {
        reply_to_caller(caller, msg, result);
    }
}

static void kernel_call_finish(struct proc * caller, message *msg, int result)
{
    if (result == VMSUSPEND) {
        save_kernel_call_for_vm(caller, msg);
    } else {
        complete_kernel_call(caller, msg, result);
    }
}

static int kernel_call_dispatch(struct proc * caller, message *msg)
{
    int call_nr;

#if DEBUG_IPC_HOOK
    hook_ipc_msgkcall(msg, caller);
#endif

    call_nr = msg->m_type - KERNEL_CALL;

    if (call_nr < 0 || call_nr >= NR_SYS_CALLS) {
        printf("SYSTEM: illegal request %d from %d.\n",
               call_nr, msg->m_source);
        return EBADREQUEST;
    }

    if (!GET_BIT(priv(caller)->s_k_call_mask, call_nr)) {
        printf("SYSTEM: denied request %d from %d.\n",
               call_nr, msg->m_source);
        return ECALLDENIED;
    }

    if (!call_vec[call_nr]) {
        printf("Unused kernel call %d from %d\n",
               call_nr, caller->p_endpoint);
        return EBADREQUEST;
    }

    return (*call_vec[call_nr])(caller, msg);
}

/*===========================================================================*
 *				kernel_call				     *
 *===========================================================================*/
/*
 * this function checks the basic syscall parameters and if accepted it
 * dispatches its handling to the right handler
 */
void kernel_call(message *m_user, struct proc *caller)
{
    message msg;
    caller->p_delivermsg_vir = (vir_bytes)m_user;

    /*
     * the ldt and cr3 of the caller process is loaded because it just've trapped
     * into the kernel or was already set in switch_to_user() before we resume
     * execution of an interrupted kernel call
     */
    if (copy_msg_from_user(m_user, &msg) != 0) {
        printf("WARNING wrong user pointer 0x%08lx from process %s / %d\n",
               (unsigned long)m_user, caller->p_name, caller->p_endpoint);
        cause_sig(proc_nr(caller), SIGSEGV);
        return;
    }

    msg.m_source = caller->p_endpoint;
    int result = kernel_call_dispatch(caller, &msg);

    /* remember who invoked the kcall so we can bill it its time */
    kbill_kcall = caller;

    kernel_call_finish(caller, &msg, result);
}

/*===========================================================================*
 *				initialize				     *
 *===========================================================================*/
typedef struct {
    int call_nr;
    int (*handler)(void);
} call_map_t;

static const call_map_t call_mapping[] = {
    { SYS_FORK, do_fork },
    { SYS_EXEC, do_exec },
    { SYS_CLEAR, do_clear },
    { SYS_EXIT, do_exit },
    { SYS_PRIVCTL, do_privctl },
    { SYS_TRACE, do_trace },
    { SYS_SETGRANT, do_setgrant },
    { SYS_RUNCTL, do_runctl },
    { SYS_UPDATE, do_update },
    { SYS_STATECTL, do_statectl },
    { SYS_KILL, do_kill },
    { SYS_GETKSIG, do_getksig },
    { SYS_ENDKSIG, do_endksig },
    { SYS_SIGSEND, do_sigsend },
    { SYS_SIGRETURN, do_sigreturn },
    { SYS_IRQCTL, do_irqctl },
    { SYS_MEMSET, do_memset },
    { SYS_VMCTL, do_vmctl },
    { SYS_UMAP, do_umap },
    { SYS_UMAP_REMOTE, do_umap_remote },
    { SYS_VUMAP, do_vumap },
    { SYS_VIRCOPY, do_vircopy },
    { SYS_PHYSCOPY, do_copy },
    { SYS_SAFECOPYFROM, do_safecopy_from },
    { SYS_SAFECOPYTO, do_safecopy_to },
    { SYS_VSAFECOPY, do_vsafecopy },
    { SYS_SAFEMEMSET, do_safememset },
    { SYS_TIMES, do_times },
    { SYS_SETALARM, do_setalarm },
    { SYS_STIME, do_stime },
    { SYS_SETTIME, do_settime },
    { SYS_VTIMER, do_vtimer },
    { SYS_ABORT, do_abort },
    { SYS_GETINFO, do_getinfo },
    { SYS_DIAGCTL, do_diagctl },
    { SYS_SPROF, do_sprofile },
    { SYS_SETMCONTEXT, do_setmcontext },
    { SYS_GETMCONTEXT, do_getmcontext },
    { SYS_SCHEDULE, do_schedule },
    { SYS_SCHEDCTL, do_schedctl },
#if defined(__i386__)
    { SYS_DEVIO, do_devio },
    { SYS_VDEVIO, do_vdevio },
    { SYS_READBIOS, do_readbios },
    { SYS_IOPENABLE, do_iopenable },
    { SYS_SDEVIO, do_sdevio },
#endif
#if defined(__arm__)
    { SYS_PADCONF, do_padconf },
#endif
};

void system_init(void)
{
    struct priv *sp;
    int i;

    for (i = 0; i < NR_IRQ_HOOKS; i++) {
        irq_hooks[i].proc_nr_e = NONE;
    }

    for (sp = BEG_PRIV_ADDR; sp < END_PRIV_ADDR; sp++) {
        tmr_inittimer(&(sp->s_alarm_timer));
    }

    memset(call_vec, 0, sizeof(call_vec));

    for (i = 0; i < (sizeof(call_mapping) / sizeof(call_mapping[0])); i++) {
        map(call_mapping[i].call_nr, call_mapping[i].handler);
    }
}
/*===========================================================================*
 *				get_priv				     *
 *===========================================================================*/
int get_priv(struct proc *rc, int priv_id)
{
    struct priv *sp;

    if (rc == NULL) {
        return EINVAL;
    }

    if (priv_id == NULL_PRIV_ID) {
        for (sp = BEG_DYN_PRIV_ADDR; sp < END_DYN_PRIV_ADDR; ++sp) {
            if (sp->s_proc_nr == NONE) {
                break;
            }
        }
        if (sp >= END_DYN_PRIV_ADDR) {
            return ENOSPC;
        }
    } else {
        if (!is_static_priv_id(priv_id)) {
            return EINVAL;
        }
        sp = &priv[priv_id];
        if (sp->s_proc_nr != NONE) {
            return EBUSY;
        }
    }

    rc->p_priv = sp;
    sp->s_proc_nr = proc_nr(rc);

    return OK;
}

/*===========================================================================*
 *				set_sendto_bit				     *
 *===========================================================================*/
void set_sendto_bit(const struct proc *rp, int id)
{
    if (!rp) {
        return;
    }

    struct priv *source_priv = priv(rp);
    const int source_id = priv_id(rp);
    const int is_invalid_target = (id_to_nr(id) == NONE);
    const int is_sending_to_self = (source_id == id);

    if (is_invalid_target || is_sending_to_self) {
        unset_sys_bit(source_priv->s_ipc_to, id);
    } else {
        set_sys_bit(source_priv->s_ipc_to, id);

        struct priv *dest_priv = priv_addr(id);
        const unsigned long can_reply_mask = ~((1UL << RECEIVE));

        if (dest_priv && (dest_priv->s_trap_mask & can_reply_mask)) {
            set_sys_bit(dest_priv->s_ipc_to, source_id);
        }
    }
}

/*===========================================================================*
 *				unset_sendto_bit			     *
 *===========================================================================*/
#include <assert.h>

void unset_sendto_bit(const struct proc *rp, int id)
{
    assert(rp != NULL);

    struct priv *source_priv = priv(rp);
    const int source_id = priv_id(rp);

    struct priv *dest_priv = priv_addr(id);
    assert(dest_priv != NULL);

    unset_sys_bit(source_priv->s_ipc_to, id);
    unset_sys_bit(dest_priv->s_ipc_to, source_id);
}

/*===========================================================================*
 *			      fill_sendto_mask				     *
 *===========================================================================*/
void fill_sendto_mask(struct proc *rp, const sys_map_t *map)
{
    for (int i = 0; i < NR_SYS_PROCS; i++) {
        if (get_sys_bit(*map, i)) {
            set_sendto_bit(rp, i);
        } else {
            unset_sendto_bit(rp, i);
        }
    }
}

/*===========================================================================*
 *				send_sig				     *
 *===========================================================================*/
int send_sig(endpoint_t ep, int sig_nr)
{
    int proc_nr;
    if (!isokendpt(ep, &proc_nr) || isemptyn(proc_nr)) {
        return EINVAL;
    }

    struct proc * const rp = proc_addr(proc_nr);
    struct priv * const priv = priv(rp);

    if (priv == NULL) {
        return ENOENT;
    }

    sigaddset(&priv->s_sig_pending, sig_nr);
    mini_notify(proc_addr(SYSTEM), rp->p_endpoint);

    return OK;
}

/*===========================================================================*
 *				cause_sig				     *
 *===========================================================================*/
void cause_sig(proc_nr_t proc_nr, int sig_nr)
{
    struct proc *rp;
    struct proc *sig_mgr_rp;
    endpoint_t sig_mgr;
    int sig_mgr_proc_nr;

    rp = proc_addr(proc_nr);
    sig_mgr = priv(rp)->s_sig_mgr;
    if (sig_mgr == SELF) {
        sig_mgr = rp->p_endpoint;
    }

    if (rp->p_endpoint == sig_mgr) {
        if (!SIGS_IS_LETHAL(sig_nr)) {
            sigaddset(&priv(rp)->s_sig_pending, sig_nr);
            if (OK != send_sig(rp->p_endpoint, SIGKSIGSM)) {
                panic("send_sig failed");
            }
            return;
        }

        endpoint_t bak_sig_mgr = priv(rp)->s_bak_sig_mgr;
        if (bak_sig_mgr != NONE && isokendpt(bak_sig_mgr, &sig_mgr_proc_nr)) {
            priv(rp)->s_sig_mgr = bak_sig_mgr;
            priv(rp)->s_bak_sig_mgr = NONE;
            sig_mgr_rp = proc_addr(sig_mgr_proc_nr);
            RTS_UNSET(sig_mgr_rp, RTS_NO_PRIV);
            sig_mgr = bak_sig_mgr;
        } else {
            proc_stacktrace(rp);
            panic("cause_sig: sig manager %d gets lethal signal %d for itself",
                  rp->p_endpoint, sig_nr);
        }
    }

    if (!sigismember(&rp->p_pending, sig_nr)) {
        sigaddset(&rp->p_pending, sig_nr);
        if (!RTS_ISSET(rp, RTS_SIGNALED)) {
            RTS_SET(rp, RTS_SIGNALED | RTS_SIG_PENDING);
            if (OK != send_sig(sig_mgr, SIGKSIG)) {
                panic("send_sig failed");
            }
        }
    }
}

/*===========================================================================*
 *				sig_delay_done				     *
 *===========================================================================*/
void sig_delay_done(struct proc *rp)
{
    if (!rp)
    {
        return;
    }

    rp->p_misc_flags &= ~MF_SIG_DELAY;
    cause_sig(proc_nr(rp), SIGSNDELAY);
}

/*===========================================================================*
 *				send_diag_sig				     *
 *===========================================================================*/
void send_diag_sig(void)
{
    for (struct priv *privp = BEG_PRIV_ADDR; privp < END_PRIV_ADDR; privp++) {
        if (privp->s_proc_nr == NONE || !privp->s_diag_sig) {
            continue;
        }

        struct proc *proc_ptr = proc_addr(privp->s_proc_nr);
        if (proc_ptr == NULL) {
            continue;
        }

        send_sig(proc_ptr->p_endpoint, SIGKMESS);
    }
}

/*===========================================================================*
 *			         clear_memreq				     *
 *===========================================================================*/
static void clear_memreq(struct proc *rp)
{
    if (rp == NULL || !RTS_ISSET(rp, RTS_VMREQUEST)) {
        return;
    }

    struct proc **link = &vmrequest;
    while (*link != NULL) {
        if (*link == rp) {
            *link = rp->p_vmrequest.nextrequestor;
            break;
        }
        link = &(*link)->p_vmrequest.nextrequestor;
    }

    RTS_UNSET(rp, RTS_VMREQUEST);
}

/*===========================================================================*
 *			         clear_ipc				     *
 *===========================================================================*/
static void remove_from_caller_queue(struct proc *proc_to_remove)
{
    int target_proc_nr;
    struct proc *target_proc;
    struct proc **link_ptr;

    okendpt(proc_to_remove->p_sendto_e, &target_proc_nr);

    target_proc = proc_addr(target_proc_nr);
    if (!target_proc) {
        return;
    }

    for (link_ptr = &target_proc->p_caller_q; *link_ptr;
         link_ptr = &(*link_ptr)->p_q_link) {
        if (*link_ptr == proc_to_remove) {
            *link_ptr = proc_to_remove->p_q_link;
#if DEBUG_ENABLE_IPC_WARNINGS
            printf("endpoint %d / %s removed from queue at %d\n",
                   proc_to_remove->p_endpoint, proc_to_remove->p_name,
                   proc_to_remove->p_sendto_e);
#endif
            break;
        }
    }
}

static void clear_ipc(struct proc *proc)
{
    if (!proc) {
        return;
    }

    if (RTS_ISSET(proc, RTS_SENDING)) {
        remove_from_caller_queue(proc);
        RTS_UNSET(proc, RTS_SENDING);
    }

    RTS_UNSET(proc, RTS_RECEIVING);
}

/*===========================================================================*
 *			         clear_endpoint				     *
 *===========================================================================*/
void clear_endpoint(struct proc *rc)
{
    if (!rc) {
        panic("clear_endpoint: called with NULL process pointer");
    }
    if (isemptyp(rc)) {
        panic("clear_endpoint: clearing an empty process slot");
    }

#if DEBUG_IPC_HOOK
    hook_ipc_clear(rc);
#endif

    RTS_SET(rc, RTS_NO_ENDPOINT);
    if (priv(rc)->s_flags & SYS_PROC) {
        priv(rc)->s_asynsize = 0;
    }

    clear_ipc(rc);

    clear_ipc_refs(rc, EDEADSRCDST);

    clear_memreq(rc);
}

/*===========================================================================*
 *			       clear_ipc_refs				     *
 *===========================================================================*/
void clear_ipc_refs(struct proc *rc, int caller_ret)
{
    int src_id;
    while ((src_id = has_pending_asend(rc, ANY)) != NULL_PRIV_ID) {
        cancel_async(proc_addr(id_to_nr(src_id)), rc);
    }

    for (struct proc *rp = BEG_PROC_ADDR; rp < END_PROC_ADDR; rp++) {
        if (isemptyp(rp)) {
            continue;
        }

        unset_sys_bit(priv(rp)->s_notify_pending, priv(rc)->s_id);
        unset_sys_bit(priv(rp)->s_asyn_pending, priv(rc)->s_id);

        if (P_BLOCKEDON(rp) == rc->p_endpoint) {
            rp->p_reg.retreg = caller_ret;
            clear_ipc(rp);
        }
    }
}

/*===========================================================================*
 *                              kernel_call_resume                           *
 *===========================================================================*/
void kernel_call_resume(struct proc *caller)
{
	assert(caller != NULL);
	assert(!RTS_ISSET(caller, RTS_SLOT_FREE));
	assert(!RTS_ISSET(caller, RTS_VMREQUEST));
	assert(caller->p_vmrequest.saved.reqmsg.m_source == caller->p_endpoint);

	message * const saved_msg = &caller->p_vmrequest.saved.reqmsg;

	const int result = kernel_call_dispatch(caller, saved_msg);

	caller->p_misc_flags &= ~MF_KCALL_RESUME;

	kernel_call_finish(caller, saved_msg, result);
}

/*===========================================================================*
 *                               sched_proc                                  *
 *===========================================================================*/
int sched_proc(struct proc *p, int priority, int quantum, int cpu, int niced)
{
	if ((priority < TASK_Q && priority != -1) || priority > NR_SCHED_QUEUES) {
		return EINVAL;
	}

	if (quantum < 1 && quantum != -1) {
		return EINVAL;
	}

#ifdef CONFIG_SMP
	if ((cpu < 0 && cpu != -1) || (cpu > 0 && (unsigned)cpu >= ncpus)) {
		return EINVAL;
	}

	if (cpu != -1 && !cpu_is_ready(cpu)) {
		return EBADCPU;
	}
#endif

	if (proc_is_runnable(p)) {
#ifdef CONFIG_SMP
		if (cpu != -1 && cpu != p->p_cpu) {
			smp_schedule_migrate_proc(p, cpu);
		}
#endif
		RTS_SET(p, RTS_NO_QUANTUM);
	}

	if (priority != -1) {
		p->p_priority = priority;
	}

	if (quantum != -1) {
		p->p_quantum_size_ms = quantum;
		p->p_cpu_time_left = ms_2_cpu_time(quantum);
	}

#ifdef CONFIG_SMP
	if (cpu != -1) {
		p->p_cpu = cpu;
	}
#endif

	if (niced) {
		p->p_misc_flags |= MF_NICED;
	} else {
		p->p_misc_flags &= ~MF_NICED;
	}

	RTS_UNSET(p, RTS_NO_QUANTUM);

	return OK;
}

/*===========================================================================*
 *				add_ipc_filter				     *
 *===========================================================================*/
int add_ipc_filter(struct proc *rp, int type, vir_bytes address,
	size_t length)
{
	if (type != IPCF_BLACKLIST && type != IPCF_WHITELIST) {
		return EINVAL;
	}
	if (length % sizeof(ipc_filter_el_t) != 0) {
		return EINVAL;
	}

	const size_t num_elements = length / sizeof(ipc_filter_el_t);
	if (num_elements == 0 || num_elements > IPCF_MAX_ELEMENTS) {
		return E2BIG;
	}

	ipc_filter_t *ipcf;
	IPCF_POOL_ALLOCATE_SLOT(type, &ipcf);
	if (ipcf == NULL) {
		return ENOMEM;
	}

	ipcf->num_elements = (int)num_elements;
	ipcf->next = NULL;

	int r = data_copy(rp->p_endpoint, address,
		KERNEL, (vir_bytes)ipcf->elements, length);

	if (r == OK) {
		r = check_ipc_filter(ipcf, TRUE);
	}

	if (r != OK) {
		IPCF_POOL_FREE_SLOT(ipcf);
		return r;
	}

	ipc_filter_t **ipcfp = &priv(rp)->s_ipcf;
	while (*ipcfp != NULL) {
		ipcfp = &(*ipcfp)->next;
	}
	*ipcfp = ipcf;

	return OK;
}

/*===========================================================================*
 *				clear_ipc_filters			     *
 *===========================================================================*/
void clear_ipc_filters(struct proc *process)
{
	ipc_filter_t *current_filter = priv(process)->s_ipcf;

	while (current_filter != NULL) {
		ipc_filter_t *next_filter = current_filter->next;
		IPCF_POOL_FREE_SLOT(current_filter);
		current_filter = next_filter;
	}

	priv(process)->s_ipcf = NULL;

	if (process->p_endpoint == VM_PROC_NR && vmrequest != NULL) {
		if (send_sig(VM_PROC_NR, SIGKMEM) != OK) {
			panic("send_sig failed");
		}
	}
}

/*===========================================================================*
 *				check_ipc_filter			     *
 *===========================================================================*/
int check_ipc_filter(ipc_filter_t *ipcf, int fill_flags)
{
	if (ipcf == NULL) {
		return OK;
	}

	if (ipcf->num_elements < 0) {
		return EINVAL;
	}

	if (ipcf->num_elements > 0 && ipcf->elements == NULL) {
		return EINVAL;
	}

	int calculated_flags = 0;
	for (int i = 0; i < ipcf->num_elements; i++) {
		ipc_filter_el_t *element = &ipcf->elements[i];
		if (!IPCF_EL_CHECK(element)) {
			return EINVAL;
		}
		calculated_flags |= element->flags;
	}

	if (fill_flags) {
		ipcf->flags = calculated_flags;
		return OK;
	}

	return (ipcf->flags == calculated_flags) ? OK : EINVAL;
}

/*===========================================================================*
 *				allow_ipc_filtered_msg			     *
 *===========================================================================*/
int allow_ipc_filtered_msg(struct proc *rp, endpoint_t src_e,
	vir_bytes m_src_v, message *m_src_p)
{
	ipc_filter_t *ipcf;
	const ipc_filter_t *current_filter;
	message m_buff;
	int allow;
	int i;

	ipcf = priv(rp)->s_ipcf;
	if (ipcf == NULL) {
		return TRUE; /* no IPC filters, always allow */
	}

	if (m_src_p == NULL) {
		int get_mtype = FALSE;
		assert(m_src_v != 0);

		for (current_filter = ipcf; current_filter != NULL;
		    current_filter = current_filter->next) {
#if DEBUG_DUMPIPCF
			get_mtype = TRUE;
			break;
#else
			if (current_filter->flags & IPCF_MATCH_M_TYPE) {
				get_mtype = TRUE;
				break;
			}
#endif
		}

		if (get_mtype) {
			int r = data_copy(src_e,
			    m_src_v + offsetof(message, m_type), KERNEL,
			    (vir_bytes)&m_buff.m_type, sizeof(m_buff.m_type));
			if (r != OK) {
				/* allow for now, this will fail later anyway */
#if DEBUG_DUMPIPCF
				printf("KERNEL: allow_ipc_filtered_msg: data "
				    "copy error %d, allowing message...\n", r);
#endif
				return TRUE;
			}
		}
		m_src_p = &m_buff;
	}

	m_src_p->m_source = src_e;

	allow = (ipcf->type == IPCF_BLACKLIST);

	for (current_filter = ipcf; current_filter != NULL;
	    current_filter = current_filter->next) {
		for (i = 0; i < current_filter->num_elements; i++) {
			if (IPCF_EL_MATCH(&current_filter->elements[i],
			    m_src_p)) {
				allow = (current_filter->type == IPCF_WHITELIST);
				break;
			}
		}
	}

#if DEBUG_DUMPIPCF
	printmsg(m_src_p, proc_addr(_ENDPOINT_P(src_e)), rp, allow ? '+' : '-',
	    TRUE /*printparams*/);
#endif

	return allow;
}

/*===========================================================================*
 *			  allow_ipc_filtered_memreq			     *
 *===========================================================================*/
int allow_ipc_filtered_memreq(struct proc *src_rp, struct proc *dst_rp)
{
	(void)src_rp;
	(void)dst_rp;

	struct proc *vmp = proc_addr(VM_PROC_NR);

	if (vmp == NULL) {
		return FALSE;
	}

	if (priv(vmp)->s_ipcf == NULL) {
		return TRUE;
	}

	message m_buf;
	m_buf.m_type = NOTIFY_MESSAGE;

	if (!allow_ipc_filtered_msg(vmp, SYSTEM, 0, &m_buf)) {
		return FALSE;
	}

	return TRUE;
}

/*===========================================================================*
 *                             priv_add_irq                                  *
 *===========================================================================*/
int priv_add_irq(const struct proc *rp, int irq)
{
    struct priv *priv = priv(rp);
    int i;

    priv->s_flags |= CHECK_IRQ;

    for (i = 0; i < priv->s_nr_irq; i++) {
        if (priv->s_irq_tab[i] == irq) {
            return OK;
        }
    }

    if (priv->s_nr_irq >= NR_IRQ) {
        return ENOMEM;
    }

    priv->s_irq_tab[priv->s_nr_irq] = irq;
    priv->s_nr_irq++;

    return OK;
}

/*===========================================================================*
 *                             priv_add_io                                   *
 *===========================================================================*/
int priv_add_io(struct proc *rp, const struct io_range *ior)
{
	struct priv *priv = priv(rp);

	priv->s_flags |= CHECK_IO_PORT;

	for (int i = 0; i < priv->s_nr_io_range; i++) {
		if (priv->s_io_tab[i].ior_base == ior->ior_base &&
		    priv->s_io_tab[i].ior_limit == ior->ior_limit) {
			return OK;
		}
	}

	if (priv->s_nr_io_range >= NR_IO_RANGE) {
		printf("do_privctl: %d already has %d i/o ranges.\n",
		       rp->p_endpoint, priv->s_nr_io_range);
		return ENOMEM;
	}

	priv->s_io_tab[priv->s_nr_io_range++] = *ior;
	return OK;
}

/*===========================================================================*
 *                             priv_add_mem                                  *
 *===========================================================================*/
int priv_add_mem(struct proc *rp, const struct minix_mem_range *memr)
{
	if (!rp || !memr) {
		return EINVAL;
	}

	struct priv *priv = priv(rp);

	priv->s_flags |= CHECK_MEM;

	for (int i = 0; i < priv->s_nr_mem_range; i++) {
		if (priv->s_mem_tab[i].mr_base == memr->mr_base &&
		    priv->s_mem_tab[i].mr_limit == memr->mr_limit) {
			return OK;
		}
	}

	if (priv->s_nr_mem_range >= NR_MEM_RANGE) {
		printf("do_privctl: %d: no more space for mem ranges\n",
		       rp->p_endpoint);
		return ENOMEM;
	}

	priv->s_mem_tab[priv->s_nr_mem_range++] = *memr;

	return OK;
}

