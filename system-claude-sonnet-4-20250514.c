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

static void kernel_call_finish(struct proc *caller, message *msg, int result)
{
    if (result == VMSUSPEND) {
        assert(RTS_ISSET(caller, RTS_VMREQUEST));
        assert(caller->p_vmrequest.type == VMSTYPE_KERNELCALL);
        caller->p_vmrequest.saved.reqmsg = *msg;
        caller->p_misc_flags |= MF_KCALL_RESUME;
        return;
    }

    caller->p_vmrequest.saved.reqmsg.m_source = NONE;
    
    if (result == EDONTREPLY) {
        return;
    }

    msg->m_source = SYSTEM;
    msg->m_type = result;

#if DEBUG_IPC_HOOK
    hook_ipc_msgkresult(msg, caller);
#endif

    if (copy_msg_to_user(msg, (message *)caller->p_delivermsg_vir) != 0) {
        printf("WARNING wrong user pointer 0x%08x from process %s / %d\n",
               caller->p_delivermsg_vir,
               caller->p_name,
               caller->p_endpoint);
        cause_sig(proc_nr(caller), SIGSEGV);
    }
}

static int kernel_call_dispatch(struct proc * caller, message *msg)
{
    int result = OK;
    int call_nr;

    if (!caller || !msg) {
        return EBADREQUEST;
    }

#if DEBUG_IPC_HOOK
    hook_ipc_msgkcall(msg, caller);
#endif

    call_nr = msg->m_type - KERNEL_CALL;

    if (call_nr < 0 || call_nr >= NR_SYS_CALLS) {
        printf("SYSTEM: illegal request %d from %d.\n", call_nr, msg->m_source);
        return EBADREQUEST;
    }

    if (!GET_BIT(priv(caller)->s_k_call_mask, call_nr)) {
        printf("SYSTEM: denied request %d from %d.\n", call_nr, msg->m_source);
        return ECALLDENIED;
    }

    if (!call_vec[call_nr]) {
        printf("Unused kernel call %d from %d\n", call_nr, caller->p_endpoint);
        return EBADREQUEST;
    }

    result = (*call_vec[call_nr])(caller, msg);
    return result;
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
    int result = OK;
    message msg;

    if (!m_user || !caller) {
        return;
    }

    caller->p_delivermsg_vir = (vir_bytes) m_user;

    if (copy_msg_from_user(m_user, &msg) != 0) {
        printf("WARNING wrong user pointer 0x%08x from process %s / %d\n",
               m_user, caller->p_name, caller->p_endpoint);
        cause_sig(proc_nr(caller), SIGSEGV);
        return;
    }

    msg.m_source = caller->p_endpoint;
    result = kernel_call_dispatch(caller, &msg);

    kbill_kcall = caller;
    kernel_call_finish(caller, &msg, result);
}

/*===========================================================================*
 *				initialize				     *
 *===========================================================================*/
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

    for (i = 0; i < NR_SYS_CALLS; i++) {
        call_vec[i] = NULL;
    }

    map(SYS_FORK, do_fork);
    map(SYS_EXEC, do_exec);
    map(SYS_CLEAR, do_clear);
    map(SYS_EXIT, do_exit);
    map(SYS_PRIVCTL, do_privctl);
    map(SYS_TRACE, do_trace);
    map(SYS_SETGRANT, do_setgrant);
    map(SYS_RUNCTL, do_runctl);
    map(SYS_UPDATE, do_update);
    map(SYS_STATECTL, do_statectl);

    map(SYS_KILL, do_kill);
    map(SYS_GETKSIG, do_getksig);
    map(SYS_ENDKSIG, do_endksig);
    map(SYS_SIGSEND, do_sigsend);
    map(SYS_SIGRETURN, do_sigreturn);

    map(SYS_IRQCTL, do_irqctl);
#if defined(__i386__)
    map(SYS_DEVIO, do_devio);
    map(SYS_VDEVIO, do_vdevio);
#endif

    map(SYS_MEMSET, do_memset);
    map(SYS_VMCTL, do_vmctl);

    map(SYS_UMAP, do_umap);
    map(SYS_UMAP_REMOTE, do_umap_remote);
    map(SYS_VUMAP, do_vumap);
    map(SYS_VIRCOPY, do_vircopy);
    map(SYS_PHYSCOPY, do_copy);
    map(SYS_SAFECOPYFROM, do_safecopy_from);
    map(SYS_SAFECOPYTO, do_safecopy_to);
    map(SYS_VSAFECOPY, do_vsafecopy);

    map(SYS_SAFEMEMSET, do_safememset);

    map(SYS_TIMES, do_times);
    map(SYS_SETALARM, do_setalarm);
    map(SYS_STIME, do_stime);
    map(SYS_SETTIME, do_settime);
    map(SYS_VTIMER, do_vtimer);

    map(SYS_ABORT, do_abort);
    map(SYS_GETINFO, do_getinfo);
    map(SYS_DIAGCTL, do_diagctl);

    map(SYS_SPROF, do_sprofile);

#if defined(__arm__)
    map(SYS_PADCONF, do_padconf);
#endif

#if defined(__i386__)
    map(SYS_READBIOS, do_readbios);
    map(SYS_IOPENABLE, do_iopenable);
    map(SYS_SDEVIO, do_sdevio);
#endif

    map(SYS_SETMCONTEXT, do_setmcontext);
    map(SYS_GETMCONTEXT, do_getmcontext);

    map(SYS_SCHEDULE, do_schedule);
    map(SYS_SCHEDCTL, do_schedctl);
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
        if (priv[priv_id].s_proc_nr != NONE) {
            return EBUSY;
        }
        sp = &priv[priv_id];
    }

    rc->p_priv = sp;
    rc->p_priv->s_proc_nr = proc_nr(rc);

    return OK;
}

/*===========================================================================*
 *				set_sendto_bit				     *
 *===========================================================================*/
void set_sendto_bit(const struct proc *rp, int id)
{
  if (!rp || id_to_nr(id) == NONE || priv_id(rp) == id) {
    if (rp) {
      unset_sys_bit(priv(rp)->s_ipc_to, id);
    }
    return;
  }

  struct priv *sender_priv = priv(rp);
  struct priv *receiver_priv = priv_addr(id);
  
  if (!sender_priv || !receiver_priv) {
    return;
  }

  set_sys_bit(sender_priv->s_ipc_to, id);

  if (receiver_priv->s_trap_mask & ~(1 << RECEIVE)) {
    set_sys_bit(receiver_priv->s_ipc_to, priv_id(rp));
  }
}

/*===========================================================================*
 *				unset_sendto_bit			     *
 *===========================================================================*/
void unset_sendto_bit(const struct proc *rp, int id)
{
    if (!rp || id < 0) {
        return;
    }
    
    struct priv *rp_priv = priv(rp);
    struct priv *id_priv = priv_addr(id);
    
    if (!rp_priv || !id_priv) {
        return;
    }
    
    unset_sys_bit(rp_priv->s_ipc_to, id);
    unset_sys_bit(id_priv->s_ipc_to, priv_id(rp));
}

/*===========================================================================*
 *			      fill_sendto_mask				     *
 *===========================================================================*/
void fill_sendto_mask(const struct proc *rp, const sys_map_t *map)
{
  if (!rp || !map) {
    return;
  }

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
    struct proc *rp;
    struct priv *priv;
    int proc_nr;

    if (!isokendpt(ep, &proc_nr) || isemptyn(proc_nr)) {
        return EINVAL;
    }

    rp = proc_addr(proc_nr);
    if (!rp) {
        return EINVAL;
    }

    priv = priv(rp);
    if (!priv) {
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
  struct proc *rp, *sig_mgr_rp;
  endpoint_t sig_mgr;
  int sig_mgr_proc_nr;

  rp = proc_addr(proc_nr);
  sig_mgr = priv(rp)->s_sig_mgr;
  if (sig_mgr == SELF) {
    sig_mgr = rp->p_endpoint;
  }

  if (rp->p_endpoint == sig_mgr) {
    handle_self_signal(rp, sig_nr, proc_nr);
    return;
  }

  if (!sigismember(&rp->p_pending, sig_nr)) {
    sigaddset(&rp->p_pending, sig_nr);
    if (!RTS_ISSET(rp, RTS_SIGNALED)) {
      RTS_SET(rp, RTS_SIGNALED | RTS_SIG_PENDING);
      if (send_sig(sig_mgr, SIGKSIG) != OK) {
        panic("send_sig failed");
      }
    }
  }
}

static void handle_self_signal(struct proc *rp, int sig_nr, proc_nr_t proc_nr)
{
  endpoint_t backup_sig_mgr;
  struct proc *sig_mgr_rp;
  int sig_mgr_proc_nr;

  if (SIGS_IS_LETHAL(sig_nr)) {
    backup_sig_mgr = priv(rp)->s_bak_sig_mgr;
    if (backup_sig_mgr != NONE && isokendpt(backup_sig_mgr, &sig_mgr_proc_nr)) {
      priv(rp)->s_sig_mgr = backup_sig_mgr;
      priv(rp)->s_bak_sig_mgr = NONE;
      sig_mgr_rp = proc_addr(sig_mgr_proc_nr);
      RTS_UNSET(sig_mgr_rp, RTS_NO_PRIV);
      cause_sig(proc_nr, sig_nr);
      return;
    }
    proc_stacktrace(rp);
    panic("cause_sig: sig manager %d gets lethal signal %d for itself",
          rp->p_endpoint, sig_nr);
  }
  
  sigaddset(&priv(rp)->s_sig_pending, sig_nr);
  if (send_sig(rp->p_endpoint, SIGKSIGSM) != OK) {
    panic("send_sig failed");
  }
}

/*===========================================================================*
 *				sig_delay_done				     *
 *===========================================================================*/
void sig_delay_done(struct proc *rp)
{
    if (rp == NULL) {
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
  struct priv *privp;
  endpoint_t ep;

  for (privp = BEG_PRIV_ADDR; privp < END_PRIV_ADDR; privp++) {
    if (privp->s_proc_nr == NONE || privp->s_diag_sig != TRUE) {
      continue;
    }
    
    struct proc *proc = proc_addr(privp->s_proc_nr);
    if (proc == NULL) {
      continue;
    }
    
    ep = proc->p_endpoint;
    send_sig(ep, SIGKMESS);
  }
}

/*===========================================================================*
 *			         clear_memreq				     *
 *===========================================================================*/
static void clear_memreq(struct proc *rp)
{
  struct proc **rpp;

  if (rp == NULL || !RTS_ISSET(rp, RTS_VMREQUEST))
    return;

  for (rpp = &vmrequest; *rpp != NULL; rpp = &(*rpp)->p_vmrequest.nextrequestor) {
    if (*rpp == rp) {
      *rpp = rp->p_vmrequest.nextrequestor;
      break;
    }
  }

  RTS_UNSET(rp, RTS_VMREQUEST);
}

/*===========================================================================*
 *			         clear_ipc				     *
 *===========================================================================*/
static void clear_ipc(register struct proc *rc)
{
    struct proc **xpp;
    int target_proc;

    if (!rc || !RTS_ISSET(rc, RTS_SENDING)) {
        goto cleanup_receiving;
    }

    if (okendpt(rc->p_sendto_e, &target_proc) != OK) {
        goto cleanup_sending;
    }

    xpp = &proc_addr(target_proc)->p_caller_q;
    while (*xpp) {
        if (*xpp == rc) {
            *xpp = (*xpp)->p_q_link;
#if DEBUG_ENABLE_IPC_WARNINGS
            printf("endpoint %d / %s removed from queue at %d\n",
                rc->p_endpoint, rc->p_name, rc->p_sendto_e);
#endif
            break;
        }
        xpp = &(*xpp)->p_q_link;
    }

cleanup_sending:
    RTS_UNSET(rc, RTS_SENDING);

cleanup_receiving:
    RTS_UNSET(rc, RTS_RECEIVING);
}

/*===========================================================================*
 *			         clear_endpoint				     *
 *===========================================================================*/
void clear_endpoint(struct proc * rc)
{
    if (rc == NULL) {
        panic("clear_proc: null process pointer");
    }
    
    if (isemptyp(rc)) {
        panic("clear_proc: empty process: %d", rc->p_endpoint);
    }

#if DEBUG_IPC_HOOK
    hook_ipc_clear(rc);
#endif

    RTS_SET(rc, RTS_NO_ENDPOINT);
    
    if (priv(rc) != NULL && (priv(rc)->s_flags & SYS_PROC)) {
        priv(rc)->s_asynsize = 0;
    }

    clear_ipc(rc);
    clear_ipc_refs(rc, EDEADSRCDST);
    clear_memreq(rc);
}

/*===========================================================================*
 *			       clear_ipc_refs				     *
 *===========================================================================*/
void clear_ipc_refs(
  register struct proc *rc,
  int caller_ret
)
{
  struct proc *rp;
  int src_id;

  if (rc == NULL) {
    return;
  }

  while ((src_id = has_pending_asend(rc, ANY)) != NULL_PRIV_ID) {
    struct proc *src_proc = proc_addr(id_to_nr(src_id));
    if (src_proc != NULL) {
      cancel_async(src_proc, rc);
    }
  }

  for (rp = BEG_PROC_ADDR; rp < END_PROC_ADDR; rp++) {
    if (isemptyp(rp) || rp == rc) {
      continue;
    }

    struct priv *rp_priv = priv(rp);
    struct priv *rc_priv = priv(rc);
    
    if (rp_priv != NULL && rc_priv != NULL) {
      unset_sys_bit(rp_priv->s_notify_pending, rc_priv->s_id);
      unset_sys_bit(rp_priv->s_asyn_pending, rc_priv->s_id);
    }

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
	int result;

	if (!caller) {
		return;
	}

	assert(!RTS_ISSET(caller, RTS_SLOT_FREE));
	assert(!RTS_ISSET(caller, RTS_VMREQUEST));
	assert(caller->p_vmrequest.saved.reqmsg.m_source == caller->p_endpoint);

	result = kernel_call_dispatch(caller, &caller->p_vmrequest.saved.reqmsg);
	
	caller->p_misc_flags &= ~MF_KCALL_RESUME;
	kernel_call_finish(caller, &caller->p_vmrequest.saved.reqmsg, result);
}

/*===========================================================================*
 *                               sched_proc                                  *
 *===========================================================================*/
int sched_proc(struct proc *p, int priority, int quantum, int cpu, int niced)
{
	if ((priority < TASK_Q && priority != -1) || priority > NR_SCHED_QUEUES)
		return EINVAL;

	if (quantum < 1 && quantum != -1)
		return EINVAL;

#ifdef CONFIG_SMP
	if ((cpu < 0 && cpu != -1) || (cpu > 0 && (unsigned) cpu >= ncpus))
		return EINVAL;
	if (cpu != -1 && !cpu_is_ready(cpu))
		return EBADCPU;
#endif

	if (proc_is_runnable(p)) {
#ifdef CONFIG_SMP
		if (p->p_cpu != cpuid && cpu != -1 && cpu != p->p_cpu) {
			smp_schedule_migrate_proc(p, cpu);
		}
#endif
		RTS_SET(p, RTS_NO_QUANTUM);
	}

	if (priority != -1)
		p->p_priority = priority;
	if (quantum != -1) {
		p->p_quantum_size_ms = quantum;
		p->p_cpu_time_left = ms_2_cpu_time(quantum);
	}
#ifdef CONFIG_SMP
	if (cpu != -1)
		p->p_cpu = cpu;
#endif

	if (niced)
		p->p_misc_flags |= MF_NICED;
	else
		p->p_misc_flags &= ~MF_NICED;

	RTS_UNSET(p, RTS_NO_QUANTUM);

	return OK;
}

/*===========================================================================*
 *				add_ipc_filter				     *
 *===========================================================================*/
int add_ipc_filter(struct proc *rp, int type, vir_bytes address,
	size_t length)
{
	int num_elements, r;
	ipc_filter_t *ipcf, **ipcfp;

	if (!rp)
		return EINVAL;

	if (type != IPCF_BLACKLIST && type != IPCF_WHITELIST)
		return EINVAL;

	if (length % sizeof(ipc_filter_el_t) != 0)
		return EINVAL;

	num_elements = length / sizeof(ipc_filter_el_t);
	if (num_elements <= 0 || num_elements > IPCF_MAX_ELEMENTS)
		return E2BIG;

	IPCF_POOL_ALLOCATE_SLOT(type, &ipcf);
	if (ipcf == NULL)
		return ENOMEM;

	ipcf->num_elements = num_elements;
	ipcf->next = NULL;
	
	r = data_copy(rp->p_endpoint, address, KERNEL, (vir_bytes)ipcf->elements, length);
	if (r != OK) {
		IPCF_POOL_FREE_SLOT(ipcf);
		return r;
	}

	r = check_ipc_filter(ipcf, TRUE);
	if (r != OK) {
		IPCF_POOL_FREE_SLOT(ipcf);
		return r;
	}

	for (ipcfp = &priv(rp)->s_ipcf; *ipcfp != NULL; ipcfp = &(*ipcfp)->next)
		;
	*ipcfp = ipcf;

	return OK;
}

/*===========================================================================*
 *				clear_ipc_filters			     *
 *===========================================================================*/
void clear_ipc_filters(struct proc *rp)
{
	ipc_filter_t *curr_ipcf, *ipcf;

	if (rp == NULL) {
		return;
	}

	ipcf = priv(rp)->s_ipcf;
	while (ipcf != NULL) {
		curr_ipcf = ipcf;
		ipcf = ipcf->next;
		IPCF_POOL_FREE_SLOT(curr_ipcf);
	}

	priv(rp)->s_ipcf = NULL;

	if (rp->p_endpoint == VM_PROC_NR && vmrequest != NULL) {
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
    ipc_filter_el_t *ipcf_el;
    int i, num_elements, flags;

    if (ipcf == NULL)
        return OK;

    if (ipcf->elements == NULL)
        return EINVAL;

    num_elements = ipcf->num_elements;
    if (num_elements < 0)
        return EINVAL;

    flags = 0;
    for (i = 0; i < num_elements; i++) {
        ipcf_el = &ipcf->elements[i];
        if (ipcf_el == NULL || !IPCF_EL_CHECK(ipcf_el))
            return EINVAL;
        flags |= ipcf_el->flags;
    }

    if (fill_flags) {
        ipcf->flags = flags;
    } else {
        if (ipcf->flags != flags)
            return EINVAL;
    }

    return OK;
}

/*===========================================================================*
 *				allow_ipc_filtered_msg			     *
 *===========================================================================*/
int allow_ipc_filtered_msg(struct proc *rp, endpoint_t src_e,
	vir_bytes m_src_v, message *m_src_p)
{
	int i, r, num_elements, allow;
	ipc_filter_t *ipcf;
	ipc_filter_el_t *ipcf_el;
	message m_buff;
	int get_mtype = 0;

	ipcf = priv(rp)->s_ipcf;
	if (ipcf == NULL)
		return 1;

	if (m_src_p == NULL) {
		if (m_src_v == 0)
			return 1;

		ipcf = priv(rp)->s_ipcf;
		while (ipcf) {
			if (ipcf->flags & IPCF_MATCH_M_TYPE) {
				get_mtype = 1;
				break;
			}
			ipcf = ipcf->next;
		}
		ipcf = priv(rp)->s_ipcf;

		if (get_mtype) {
			r = data_copy(src_e,
			    m_src_v + offsetof(message, m_type), KERNEL,
			    (vir_bytes)&m_buff.m_type, sizeof(m_buff.m_type));
			if (r != OK)
				return 1;
		}
		m_src_p = &m_buff;
	}

	m_src_p->m_source = src_e;

	allow = (ipcf->type == IPCF_BLACKLIST);
	while (ipcf) {
		if (allow != (ipcf->type == IPCF_WHITELIST)) {
			num_elements = ipcf->num_elements;
			for (i = 0; i < num_elements; i++) {
				ipcf_el = &ipcf->elements[i];
				if (IPCF_EL_MATCH(ipcf_el, m_src_p)) {
					allow = (ipcf->type == IPCF_WHITELIST);
					break;
				}
			}
		}
		ipcf = ipcf->next;
	}

	return allow;
}

/*===========================================================================*
 *			  allow_ipc_filtered_memreq			     *
 *===========================================================================*/
int allow_ipc_filtered_memreq(struct proc *src_rp, struct proc *dst_rp)
{
    struct proc *vmp;
    message m_buf;

    if (!src_rp || !dst_rp) {
        return FALSE;
    }

    vmp = proc_addr(VM_PROC_NR);
    if (!vmp) {
        return FALSE;
    }

    if (priv(vmp)->s_ipcf == NULL) {
        return TRUE;
    }

    m_buf.m_type = NOTIFY_MESSAGE;
    if (!allow_ipc_filtered_msg(vmp, SYSTEM, 0, &m_buf)) {
        return FALSE;
    }

    return TRUE;
}

/*===========================================================================*
 *                             priv_add_irq                                  *
 *===========================================================================*/
int priv_add_irq(struct proc *rp, int irq)
{
        struct priv *priv;
        int i;

        if (rp == NULL) {
                return EINVAL;
        }

        priv = priv(rp);
        if (priv == NULL) {
                return EINVAL;
        }

        if (irq < 0) {
                return EINVAL;
        }

        priv->s_flags |= CHECK_IRQ;

        for (i = 0; i < priv->s_nr_irq; i++) {
                if (priv->s_irq_tab[i] == irq) {
                        return OK;
                }
        }

        if (priv->s_nr_irq >= NR_IRQ) {
                printf("do_privctl: %d already has %d irq's.\n",
                        rp->p_endpoint, priv->s_nr_irq);
                return ENOMEM;
        }

        priv->s_irq_tab[priv->s_nr_irq] = irq;
        priv->s_nr_irq++;
        return OK;
}

/*===========================================================================*
 *                             priv_add_io                                   *
 *===========================================================================*/
int priv_add_io(struct proc *rp, struct io_range *ior)
{
        struct priv *priv;
        int i;

        if (!rp || !ior) {
                return EINVAL;
        }

        priv = priv(rp);
        if (!priv) {
                return EINVAL;
        }

        priv->s_flags |= CHECK_IO_PORT;

        for (i = 0; i < priv->s_nr_io_range; i++) {
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

        priv->s_io_tab[priv->s_nr_io_range] = *ior;
        priv->s_nr_io_range++;
        return OK;
}

/*===========================================================================*
 *                             priv_add_mem                                  *
 *===========================================================================*/
int priv_add_mem(struct proc *rp, struct minix_mem_range *memr)
{
    struct priv *priv;
    int i;

    if (!rp || !memr) {
        return EINVAL;
    }

    priv = priv(rp);
    if (!priv) {
        return EINVAL;
    }

    priv->s_flags |= CHECK_MEM;

    for (i = 0; i < priv->s_nr_mem_range; i++) {
        if (priv->s_mem_tab[i].mr_base == memr->mr_base &&
            priv->s_mem_tab[i].mr_limit == memr->mr_limit) {
            return OK;
        }
    }

    if (priv->s_nr_mem_range >= NR_MEM_RANGE) {
        printf("do_privctl: %d already has %d mem ranges.\n",
               rp->p_endpoint, priv->s_nr_mem_range);
        return ENOMEM;
    }

    priv->s_mem_tab[priv->s_nr_mem_range] = *memr;
    priv->s_nr_mem_range++;
    return OK;
}

