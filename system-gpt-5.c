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
    assert(caller != NULL);
    assert(msg != NULL);

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
    if (copy_msg_to_user(msg, (message *) caller->p_delivermsg_vir)) {
        printf("WARNING wrong user pointer 0x%08x from process %s / %d\n",
               caller->p_delivermsg_vir, caller->p_name, caller->p_endpoint);
        cause_sig(proc_nr(caller), SIGSEGV);
    }
}

static int kernel_call_dispatch(struct proc *caller, message *msg)
{
    int call_nr;

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

    return call_vec[call_nr](caller, msg);
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

  caller->p_delivermsg_vir = (vir_bytes)m_user;

  if (copy_msg_from_user(m_user, &msg) != 0) {
    printf("WARNING wrong user pointer %p from process %s / %d\n",
           (void *)m_user, caller->p_name, caller->p_endpoint);
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
    size_t i;

    for (i = 0U; i < (size_t)NR_IRQ_HOOKS; ++i) {
        irq_hooks[i].proc_nr_e = NONE;
    }

    for (sp = BEG_PRIV_ADDR; sp < END_PRIV_ADDR; ++sp) {
        tmr_inittimer(&sp->s_alarm_timer);
    }

    for (i = 0U; i < (size_t)NR_SYS_CALLS; ++i) {
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
        if (sp == END_DYN_PRIV_ADDR) {
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
    sp->s_proc_nr = proc_nr(rc);

    return OK;
}

/*===========================================================================*
 *				set_sendto_bit				     *
 *===========================================================================*/
void set_sendto_bit(const struct proc *rp, int id)
{
    if (rp == NULL) return;

    struct priv *sender_priv = priv(rp);
    if (sender_priv == NULL) return;

    int sender_id = priv_id(rp);
    int target_nr = id_to_nr(id);

    if (target_nr == NONE || sender_id == id) {
        unset_sys_bit(sender_priv->s_ipc_to, id);
        return;
    }

    set_sys_bit(sender_priv->s_ipc_to, id);

    struct priv *target_priv = priv_addr(id);
    if (target_priv == NULL) return;

    if (target_priv->s_trap_mask & ~(1UL << RECEIVE)) {
        set_sys_bit(target_priv->s_ipc_to, sender_id);
    }
}

/*===========================================================================*
 *				unset_sendto_bit			     *
 *===========================================================================*/
void unset_sendto_bit(const struct proc *rp, int id)
{
  if (rp == NULL) return;

  struct priv *rp_priv = priv(rp);
  if (rp_priv == NULL) return;

  struct priv *id_priv = priv_addr(id);
  if (id_priv == NULL) return;

  int rp_id = priv_id(rp);

  unset_sys_bit(rp_priv->s_ipc_to, id);
  unset_sys_bit(id_priv->s_ipc_to, rp_id);
}

/*===========================================================================*
 *			      fill_sendto_mask				     *
 *===========================================================================*/
void fill_sendto_mask(const struct proc *rp, sys_map_t *map)
{
    int i;

    if (rp == NULL || map == NULL) {
        return;
    }

    for (i = 0; i < NR_SYS_PROCS; i++) {
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
  struct priv *ppriv;
  int proc_nr;
  int r;

  if (!isokendpt(ep, &proc_nr) || isemptyn(proc_nr))
    return EINVAL;

  rp = proc_addr(proc_nr);
  ppriv = priv(rp);
  if (!ppriv)
    return ENOENT;

  r = sigaddset(&ppriv->s_sig_pending, sig_nr);
  if (r != 0)
    return EINVAL;

  r = mini_notify(proc_addr(SYSTEM), rp->p_endpoint);
  if (r != OK)
    return r;

  return OK;
}

/*===========================================================================*
 *				cause_sig				     *
 *===========================================================================*/
void cause_sig(proc_nr_t proc_nr, int sig_nr)
{
  struct proc *rp = proc_addr(proc_nr);
  struct priv *ppriv = priv(rp);
  endpoint_t ep = rp->p_endpoint;
  endpoint_t sig_mgr;
  int sig_mgr_proc_nr;

  for (;;) {
    sig_mgr = ppriv->s_sig_mgr;
    if (sig_mgr == SELF) sig_mgr = ep;

    if (ep != sig_mgr) break;

    if (SIGS_IS_LETHAL(sig_nr)) {
      endpoint_t bak = ppriv->s_bak_sig_mgr;
      if (bak != NONE && isokendpt(bak, &sig_mgr_proc_nr)) {
        ppriv->s_sig_mgr = bak;
        ppriv->s_bak_sig_mgr = NONE;
        struct proc *sig_mgr_rp = proc_addr(sig_mgr_proc_nr);
        RTS_UNSET(sig_mgr_rp, RTS_NO_PRIV);
        continue;
      }
      proc_stacktrace(rp);
      panic("cause_sig: sig manager %d gets lethal signal %d for itself", ep, sig_nr);
    }

    sigaddset(&ppriv->s_sig_pending, sig_nr);
    if (send_sig(ep, SIGKSIGSM) != OK) panic("send_sig failed");
    return;
  }

  if (!sigismember(&rp->p_pending, sig_nr)) {
    sigaddset(&rp->p_pending, sig_nr);
    if (!RTS_ISSET(rp, RTS_SIGNALED)) {
      RTS_SET(rp, RTS_SIGNALED | RTS_SIG_PENDING);
      if (send_sig(sig_mgr, SIGKSIG) != OK) panic("send_sig failed");
    }
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
  (void)cause_sig(proc_nr(rp), SIGSNDELAY);
}

/*===========================================================================*
 *				send_diag_sig				     *
 *===========================================================================*/
void send_diag_sig(void)
{
  const struct priv *privp;

  if (BEG_PRIV_ADDR >= END_PRIV_ADDR) {
    return;
  }

  for (privp = BEG_PRIV_ADDR; privp < END_PRIV_ADDR; ++privp) {
    struct proc *p;

    if (privp->s_proc_nr == NONE || privp->s_diag_sig != TRUE) {
      continue;
    }

    p = proc_addr(privp->s_proc_nr);
    if (p == NULL) {
      continue;
    }

    send_sig(p->p_endpoint, SIGKMESS);
  }
}

/*===========================================================================*
 *			         clear_memreq				     *
 *===========================================================================*/
static void clear_memreq(struct proc *rp)
{
    struct proc **pp;

    if (rp == NULL)
        return;

    if (!RTS_ISSET(rp, RTS_VMREQUEST))
        return;

    pp = &vmrequest;
    while (*pp != NULL && *pp != rp) {
        pp = &(*pp)->p_vmrequest.nextrequestor;
    }
    if (*pp == rp) {
        *pp = rp->p_vmrequest.nextrequestor;
    }

    RTS_UNSET(rp, RTS_VMREQUEST);
}

/*===========================================================================*
 *			         clear_ipc				     *
 *===========================================================================*/
static void clear_ipc(struct proc *rc)
{
  struct proc **xpp;

  if (rc == NULL) return;

  if (RTS_ISSET(rc, RTS_SENDING)) {
      int target_proc;
      int r = okendpt(rc->p_sendto_e, &target_proc);
      if (r == OK) {
          struct proc *dst = proc_addr(target_proc);
          if (dst != NULL) {
              xpp = &dst->p_caller_q;
              while (*xpp != NULL) {
                  struct proc *cur = *xpp;
                  if (cur == rc) {
                      *xpp = cur->p_q_link;
#if DEBUG_ENABLE_IPC_WARNINGS
                      printf("endpoint %d / %s removed from queue at %d\n",
                          rc->p_endpoint, rc->p_name, rc->p_sendto_e);
#endif
                      break;
                  }
                  xpp = &cur->p_q_link;
              }
          }
      }
      RTS_UNSET(rc, RTS_SENDING);
  }
  RTS_UNSET(rc, RTS_RECEIVING);
}

/*===========================================================================*
 *			         clear_endpoint				     *
 *===========================================================================*/
void clear_endpoint(struct proc *rc)
{
    struct priv *pr;

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

    pr = priv(rc);
    if (pr != NULL && (pr->s_flags & SYS_PROC)) {
        pr->s_asynsize = 0;
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
  int rc_priv_id = NULL_PRIV_ID;
  int rc_endpoint;

  if (rc == NULL || isemptyp(rc))
    return;

  rc_endpoint = rc->p_endpoint;

  if (priv(rc) != NULL)
    rc_priv_id = priv(rc)->s_id;

  while ((src_id = has_pending_asend(rc, ANY)) != NULL_PRIV_ID)
    cancel_async(proc_addr(id_to_nr(src_id)), rc);

  for (rp = BEG_PROC_ADDR; rp < END_PROC_ADDR; rp++) {
    if (isemptyp(rp))
      continue;

    if (rc_priv_id != NULL_PRIV_ID) {
      unset_sys_bit(priv(rp)->s_notify_pending, rc_priv_id);
      unset_sys_bit(priv(rp)->s_asyn_pending, rc_priv_id);
    }

    if (P_BLOCKEDON(rp) == rc_endpoint) {
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

	const int result = kernel_call_dispatch(caller, &caller->p_vmrequest.saved.reqmsg);
	caller->p_misc_flags &= ~MF_KCALL_RESUME;
	kernel_call_finish(caller, &caller->p_vmrequest.saved.reqmsg, result);
}

/*===========================================================================*
 *                               sched_proc                                  *
 *===========================================================================*/
int sched_proc(struct proc *p, int priority, int quantum, int cpu, int niced)
{
	if (p == NULL)
		return EINVAL;

	if (priority != -1 && (priority < TASK_Q || priority > NR_SCHED_QUEUES))
		return EINVAL;

	if (quantum != -1 && quantum < 1)
		return EINVAL;

#ifdef CONFIG_SMP
	if (cpu != -1) {
		if (cpu < 0 || (unsigned) cpu >= ncpus)
			return EINVAL;
		if (!cpu_is_ready(cpu))
			return EBADCPU;
	}
#endif

	int was_runnable = proc_is_runnable(p);

#ifdef CONFIG_SMP
	if (was_runnable && p->p_cpu != cpuid && cpu != -1 && cpu != p->p_cpu) {
		smp_schedule_migrate_proc(p, cpu);
	}
#endif

	if (was_runnable)
		RTS_SET(p, RTS_NO_QUANTUM);

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
int add_ipc_filter(struct proc *rp, int type, vir_bytes address, size_t length)
{
	ipc_filter_t *ipcf = NULL, **ipcfp;
	int r;
	const size_t elem_size = sizeof(ipc_filter_el_t);
	size_t elements_count;

	if (rp == NULL)
		return EINVAL;

	if (type != IPCF_BLACKLIST && type != IPCF_WHITELIST)
		return EINVAL;

	if (length % elem_size != 0)
		return EINVAL;

	elements_count = length / elem_size;
	if (elements_count == 0 || elements_count > IPCF_MAX_ELEMENTS)
		return E2BIG;

	IPCF_POOL_ALLOCATE_SLOT(type, &ipcf);
	if (ipcf == NULL)
		return ENOMEM;

	ipcf->num_elements = (int)elements_count;
	ipcf->next = NULL;

	r = data_copy(rp->p_endpoint, address, KERNEL, (vir_bytes)ipcf->elements, length);
	if (r != OK)
		goto error;

	r = check_ipc_filter(ipcf, TRUE);
	if (r != OK)
		goto error;

	ipcfp = &priv(rp)->s_ipcf;
	while (*ipcfp != NULL)
		ipcfp = &(*ipcfp)->next;
	*ipcfp = ipcf;

	return OK;

error:
	IPCF_POOL_FREE_SLOT(ipcf);
	return r;
}

/*===========================================================================*
 *				clear_ipc_filters			     *
 *===========================================================================*/
void clear_ipc_filters(struct proc *rp)
{
	ipc_filter_t *ipcf;
	ipc_filter_t *next;

	ipcf = priv(rp)->s_ipcf;
	while (ipcf != NULL) {
		next = ipcf->next;
		IPCF_POOL_FREE_SLOT(ipcf);
		ipcf = next;
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
    if (ipcf == NULL)
        return OK;

    int num_elements = ipcf->num_elements;
    ipc_filter_el_t *elements = ipcf->elements;
    int flags = 0;

    if (num_elements > 0 && elements == NULL)
        return EINVAL;

    for (int i = 0; i < num_elements; i++) {
        ipc_filter_el_t *el = &elements[i];
        if (!IPCF_EL_CHECK(el))
            return EINVAL;
        flags |= el->flags;
    }

    if (fill_flags)
        ipcf->flags = flags;
    else if (ipcf->flags != flags)
        return EINVAL;

    return OK;
}

/*===========================================================================*
 *				allow_ipc_filtered_msg			     *
 *===========================================================================*/
int allow_ipc_filtered_msg(struct proc *rp, endpoint_t src_e,
	vir_bytes m_src_v, message *m_src_p)
{
	ipc_filter_t *head, *ipcf;
	ipc_filter_el_t *ipcf_el;
	message m_buff;
	int allow, need_mtype, r, i, num_elements;

	head = priv(rp)->s_ipcf;
	if (head == NULL)
		return TRUE;

	if (m_src_p == NULL) {
		assert(m_src_v != 0);

#if DEBUG_DUMPIPCF
		need_mtype = TRUE;
#else
		need_mtype = FALSE;
		for (ipcf = head; ipcf != NULL; ipcf = ipcf->next) {
			if (ipcf->flags & IPCF_MATCH_M_TYPE) {
				need_mtype = TRUE;
				break;
			}
		}
#endif

		if (need_mtype) {
			r = data_copy(src_e,
			    m_src_v + offsetof(message, m_type), KERNEL,
			    (vir_bytes)&m_buff.m_type, sizeof(m_buff.m_type));
			if (r != OK) {
#if DEBUG_DUMPIPCF
				printf("KERNEL: allow_ipc_filtered_msg: data copy error %d, allowing message...\n", r);
#endif
				return TRUE;
			}
		}
		m_src_p = &m_buff;
	}

	m_src_p->m_source = src_e;

	allow = (head->type == IPCF_BLACKLIST);

	for (ipcf = head; ipcf != NULL; ipcf = ipcf->next) {
		int is_whitelist = (ipcf->type == IPCF_WHITELIST);

		if (allow == is_whitelist)
			continue;

		num_elements = ipcf->num_elements;
		for (i = 0; i < num_elements; i++) {
			ipcf_el = &ipcf->elements[i];
			if (IPCF_EL_MATCH(ipcf_el, m_src_p)) {
				allow = is_whitelist;
				break;
			}
		}
	}

#if DEBUG_DUMPIPCF
	printmsg(m_src_p, proc_addr(_ENDPOINT_P(src_e)), rp, allow ? '+' : '-',
	    TRUE);
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
	if (vmp == NULL)
		return FALSE;

	struct priv *vpriv = priv(vmp);
	if (vpriv == NULL)
		return FALSE;

	if (vpriv->s_ipcf == NULL)
		return TRUE;

	message m_buf = (message){0};
	m_buf.m_type = NOTIFY_MESSAGE;

	if (!allow_ipc_filtered_msg(vmp, SYSTEM, 0, &m_buf))
		return FALSE;

	return TRUE;
}

/*===========================================================================*
 *                             priv_add_irq                                  *
 *===========================================================================*/
int priv_add_irq(struct proc *rp, int irq)
{
    struct priv *prv = priv(rp);
    int i, nr;

    prv->s_flags |= CHECK_IRQ;

    nr = prv->s_nr_irq;
    for (i = 0; i < nr; i++) {
        if (prv->s_irq_tab[i] == irq) {
            return OK;
        }
    }

    if (nr >= NR_IRQ) {
        printf("do_privctl: %d already has %d irq's.\n", rp->p_endpoint, nr);
        return ENOMEM;
    }

    prv->s_irq_tab[nr] = irq;
    prv->s_nr_irq = nr + 1;

    return OK;
}

/*===========================================================================*
 *                             priv_add_io                                   *
 *===========================================================================*/
int priv_add_io(struct proc *rp, struct io_range *ior)
{
    struct priv *p;
    int i, count;

    if (rp == NULL || ior == NULL) {
        return EINVAL;
    }

    p = priv(rp);
    if (p == NULL) {
        return EINVAL;
    }

    p->s_flags |= CHECK_IO_PORT;

    count = p->s_nr_io_range;
    for (i = 0; i < count; i++) {
        struct io_range *entry = &p->s_io_tab[i];
        if (entry->ior_base == ior->ior_base && entry->ior_limit == ior->ior_limit) {
            return OK;
        }
    }

    if (count >= NR_IO_RANGE) {
        printf("do_privctl: %d already has %d i/o ranges.\n", rp->p_endpoint, count);
        return ENOMEM;
    }

    p->s_io_tab[count] = *ior;
    p->s_nr_io_range = count + 1;
    return OK;
}

/*===========================================================================*
 *                             priv_add_mem                                  *
 *===========================================================================*/
int priv_add_mem(struct proc *rp, struct minix_mem_range *memr)
{
	struct priv *prv;
	int i;

	if (rp == NULL || memr == NULL) {
		return EINVAL;
	}

	prv = priv(rp);
	if (prv == NULL) {
		return EINVAL;
	}

	prv->s_flags |= CHECK_MEM;

	for (i = 0; i < prv->s_nr_mem_range; i++) {
		if (prv->s_mem_tab[i].mr_base == memr->mr_base &&
		    prv->s_mem_tab[i].mr_limit == memr->mr_limit) {
			return OK;
		}
	}

	i = prv->s_nr_mem_range;
	if (i < 0 || i >= NR_MEM_RANGE) {
		printf("do_privctl: %d already has %d mem ranges.\n",
		       rp->p_endpoint, i);
		return ENOMEM;
	}

	prv->s_mem_tab[i] = *memr;
	prv->s_nr_mem_range = i + 1;

	return OK;
}

