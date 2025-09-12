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

static void kernel_call_finish(struct proc * caller, message *msg, int result)
{
  if (result == VMSUSPEND) {
    assert(RTS_ISSET(caller, RTS_VMREQUEST));
    assert(caller->p_vmrequest.type == VMSTYPE_KERNELCALL);
    caller->p_vmrequest.saved.reqmsg = *msg;
    caller->p_misc_flags |= MF_KCALL_RESUME;
  } else {
    caller->p_vmrequest.saved.reqmsg.m_source = NONE;
    if (result != EDONTREPLY) {
      msg->m_source = SYSTEM;
      msg->m_type = result;
#if DEBUG_IPC_HOOK
      hook_ipc_msgkresult(msg, caller);
#endif
      if (copy_msg_to_user(msg, (message *)caller->p_delivermsg_vir)) {
        printf("WARNING wrong user pointer 0x%08x from "
               "process %s / %d\n",
               caller->p_delivermsg_vir,
               caller->p_name,
               caller->p_endpoint);
        cause_sig(proc_nr(caller), SIGSEGV);
      }
    }
  }
}

static int kernel_call_dispatch(struct proc * caller, message *msg)
{
  int call_nr;

#if DEBUG_IPC_HOOK
	hook_ipc_msgkcall(msg, caller);
#endif

  call_nr = msg->m_type - KERNEL_CALL;

  /* Validate call number range. */
  if (call_nr < 0 || call_nr >= NR_SYS_CALLS) {
	  printf("SYSTEM: illegal request %d from %d.\n",
			  call_nr, msg->m_source);
	  return EBADREQUEST;
  }

  /* Check caller's permissions for this call. */
  if (!GET_BIT(priv(caller)->s_k_call_mask, call_nr)) {
	  printf("SYSTEM: denied request %d from %d.\n",
			  call_nr, msg->m_source);
	  return ECALLDENIED;
  }

  /* Dispatch the system call if implemented. */
  if (call_vec[call_nr]) {
	  return (*call_vec[call_nr])(caller, msg);
  }

  /* Handle unimplemented/unused kernel calls. */
  printf("Unused kernel call %d from %d\n",
		  call_nr, caller->p_endpoint);
  return EBADREQUEST;
}

/*===========================================================================*
 *				kernel_call				     *
 *===========================================================================*/
/*
 * this function checks the basic syscall parameters and if accepted it
 * dispatches its handling to the right handler
 */
void kernel_call(message *m_user, struct proc * caller)
{
  caller->p_delivermsg_vir = (vir_bytes) m_user;

  message msg;
  if (copy_msg_from_user(m_user, &msg) != OK) {
	  printf("WARNING wrong user pointer 0x%08x from process %s / %d\n",
			  (unsigned int)m_user, caller->p_name, caller->p_endpoint);
	  cause_sig(proc_nr(caller), SIGSEGV);
	  return;
  }

  msg.m_source = caller->p_endpoint;
  int result = kernel_call_dispatch(caller, &msg);

  kbill_kcall = caller;

  kernel_call_finish(caller, &msg, result);
}

/*===========================================================================*
 *				initialize				     *
 *===========================================================================*/
static void init_irq_hooks(void)
{
  int i;
  for (i=0; i<NR_IRQ_HOOKS; i++) {
      irq_hooks[i].proc_nr_e = NONE;
  }
}

static void init_alarm_timers(void)
{
  struct priv *sp;
  for (sp=BEG_PRIV_ADDR; sp < END_PRIV_ADDR; sp++) {
    tmr_inittimer(&(sp->s_alarm_timer));
  }
}

static void init_syscall_vectors(void)
{
  memset(call_vec, 0, sizeof(call_vec));
}

static void map_process_management_calls(void)
{
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
}

static void map_signal_handling_calls(void)
{
  map(SYS_KILL, do_kill);
  map(SYS_GETKSIG, do_getksig);
  map(SYS_ENDKSIG, do_endksig);
  map(SYS_SIGSEND, do_sigsend);
  map(SYS_SIGRETURN, do_sigreturn);
}

static void map_device_io_calls(void)
{
  map(SYS_IRQCTL, do_irqctl);
#if defined(__i386__)
  map(SYS_DEVIO, do_devio);
  map(SYS_VDEVIO, do_vdevio);
#endif
}

static void map_memory_management_calls(void)
{
  map(SYS_MEMSET, do_memset);
  map(SYS_VMCTL, do_vmctl);
}

static void map_copying_calls(void)
{
  map(SYS_UMAP, do_umap);
  map(SYS_UMAP_REMOTE, do_umap_remote);
  map(SYS_VUMAP, do_vumap);
  map(SYS_VIRCOPY, do_vircopy);
  map(SYS_PHYSCOPY, do_copy);
  map(SYS_SAFECOPYFROM, do_safecopy_from);
  map(SYS_SAFECOPYTO, do_safecopy_to);
  map(SYS_VSAFECOPY, do_vsafecopy);
}

static void map_safe_memset_calls(void)
{
  map(SYS_SAFEMEMSET, do_safememset);
}

static void map_clock_functionality_calls(void)
{
  map(SYS_TIMES, do_times);
  map(SYS_SETALARM, do_setalarm);
  map(SYS_STIME, do_stime);
  map(SYS_SETTIME, do_settime);
  map(SYS_VTIMER, do_vtimer);
}

static void map_system_control_calls(void)
{
  map(SYS_ABORT, do_abort);
  map(SYS_GETINFO, do_getinfo);
  map(SYS_DIAGCTL, do_diagctl);
}

static void map_profiling_calls(void)
{
  map(SYS_SPROF, do_sprofile);
}

static void map_arm_specific_calls(void)
{
#if defined(__arm__)
  map(SYS_PADCONF, do_padconf);
#endif
}

static void map_i386_specific_calls(void)
{
#if defined(__i386__)
  map(SYS_READBIOS, do_readbios);
  map(SYS_IOPENABLE, do_iopenable);
  map(SYS_SDEVIO, do_sdevio);
#endif
}

static void map_machine_state_calls(void)
{
  map(SYS_SETMCONTEXT, do_setmcontext);
  map(SYS_GETMCONTEXT, do_getmcontext);
}

static void map_scheduling_calls(void)
{
  map(SYS_SCHEDULE, do_schedule);
  map(SYS_SCHEDCTL, do_schedctl);
}

void system_init(void)
{
  init_irq_hooks();
  init_alarm_timers();
  init_syscall_vectors();

  map_process_management_calls();
  map_signal_handling_calls();
  map_device_io_calls();
  map_memory_management_calls();
  map_copying_calls();
  map_safe_memset_calls();
  map_clock_functionality_calls();
  map_system_control_calls();
  map_profiling_calls();
  map_arm_specific_calls();
  map_i386_specific_calls();
  map_machine_state_calls();
  map_scheduling_calls();
}
/*===========================================================================*
 *				get_priv				     *
 *===========================================================================*/
int get_priv(
  struct proc *rc,
  int priv_id
)
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
  }
  else {
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
    if (rp == NULL) {
        return;
    }

    struct priv *proc_priv = priv(rp);
    if (proc_priv == NULL) {
        return;
    }

    unsigned int *proc_ipc_to_mask_ptr = proc_priv->s_ipc_to;

    if (id_to_nr(id) == NONE || priv_id(rp) == id) {
        if (proc_ipc_to_mask_ptr != NULL) {
            unset_sys_bit(proc_ipc_to_mask_ptr, id);
        }
        return;
    }

    if (proc_ipc_to_mask_ptr != NULL) {
        set_sys_bit(proc_ipc_to_mask_ptr, id);
    } else {
        return;
    }

    struct priv *target_priv = priv_addr(id);
    if (target_priv == NULL) {
        return;
    }

    unsigned int *target_ipc_to_mask_ptr = target_priv->s_ipc_to;

    if ((target_priv->s_trap_mask & ~((1U << RECEIVE))) != 0) {
        if (target_ipc_to_mask_ptr != NULL) {
            set_sys_bit(target_ipc_to_mask_ptr, priv_id(rp));
        }
    }
}

/*===========================================================================*
 *				unset_sendto_bit			     *
 *===========================================================================*/
void unset_sendto_bit(const struct proc *rp, int id)
{
  if (rp == NULL) {
    return;
  }

  if (priv(rp) == NULL) {
    return;
  }

  if (priv_addr(id) == NULL) {
    return;
  }

  unset_sys_bit(priv(rp)->s_ipc_to, id);

  unset_sys_bit(priv_addr(id)->s_ipc_to, priv_id(rp));
}

/*===========================================================================*
 *			      fill_sendto_mask				     *
 *===========================================================================*/
void fill_sendto_mask(struct proc *rp, const sys_map_t *map)
{
  if (rp == NULL || map == NULL) {
    return;
  }

  for (int i = 0; i < NR_SYS_PROCS; ++i) {
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
int send_sig(const endpoint_t ep, const int sig_nr)
{
  struct proc *rp;
  struct priv *priv;
  int proc_nr;

  if (!isokendpt(ep, &proc_nr) || isemptyn(proc_nr)) {
    return EINVAL;
  }

  rp = proc_addr(proc_nr);
  priv = priv(rp);

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
  struct priv_struct *pp;
  endpoint_t sig_mgr;
  int sig_mgr_proc_nr;
  int send_result;

  rp = proc_addr(proc_nr);
  if (rp == NULL) {
    return;
  }

  pp = priv(rp);
  if (pp == NULL) {
    proc_stacktrace(rp);
    panic("cause_sig: proc %d (endpoint %d) has NULL priv structure",
          proc_nr, rp->p_endpoint);
  }

retry_signal_delivery:;

  sig_mgr = pp->s_sig_mgr;
  if (sig_mgr == SELF) {
    sig_mgr = rp->p_endpoint;
  }

  if (rp->p_endpoint == sig_mgr) {
    if (SIGS_IS_LETHAL(sig_nr)) {
      endpoint_t backup_sig_mgr = pp->s_bak_sig_mgr;
      if (backup_sig_mgr != NONE && isokendpt(backup_sig_mgr, &sig_mgr_proc_nr)) {
        struct proc *backup_sig_mgr_rp = proc_addr(sig_mgr_proc_nr);
        if (backup_sig_mgr_rp != NULL) {
          pp->s_sig_mgr = backup_sig_mgr;
          pp->s_bak_sig_mgr = NONE;
          RTS_UNSET(backup_sig_mgr_rp, RTS_NO_PRIV);
          goto retry_signal_delivery;
        } else {
          proc_stacktrace(rp);
          panic("cause_sig: isokendpt passed for backup_sig_mgr %d but proc_addr failed for %d",
                backup_sig_mgr, sig_mgr_proc_nr);
        }
      } else {
        proc_stacktrace(rp);
        panic("cause_sig: sig manager %d gets lethal signal %d for itself, no valid backup",
              rp->p_endpoint, sig_nr);
      }
    } else {
      sigaddset(&pp->s_sig_pending, sig_nr);
      send_result = send_sig(rp->p_endpoint, SIGKSIGSM);
      if (OK != send_result) {
        panic("cause_sig: send_sig to self (SIGKSIGSM) failed for proc %d, endpoint %d: %d",
              proc_nr, rp->p_endpoint, send_result);
      }
      return;
    }
  }

  if (!sigismember(&rp->p_pending, sig_nr)) {
    sigaddset(&rp->p_pending, sig_nr);

    if (!RTS_ISSET(rp, RTS_SIGNALED)) {
      RTS_SET(rp, RTS_SIGNALED | RTS_SIG_PENDING);
      send_result = send_sig(sig_mgr, SIGKSIG);
      if (OK != send_result) {
        panic("cause_sig: send_sig to signal manager %d failed for proc %d: %d",
              sig_mgr, rp->p_endpoint, send_result);
      }
    }
  }
}

/*===========================================================================*
 *				sig_delay_done				     *
 *===========================================================================*/
void sig_delay_done(struct proc *rp) {
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

  for (privp = BEG_PRIV_ADDR; privp < END_PRIV_ADDR; privp++) {
    if (privp->s_proc_nr != NONE && privp->s_diag_sig == TRUE) {
      struct proc *target_proc = proc_addr(privp->s_proc_nr);
      if (target_proc != NULL) {
        endpoint_t ep = target_proc->p_endpoint;
        send_sig(ep, SIGKMESS);
      }
    }
  }
}

/*===========================================================================*
 *			         clear_memreq				     *
 *===========================================================================*/
static void clear_memreq(struct proc *rp)
{
  struct proc **current_ptr_to_next;

  if (!RTS_ISSET(rp, RTS_VMREQUEST)) {
    return;
  }

  current_ptr_to_next = &vmrequest;

  while (*current_ptr_to_next != NULL) {
    if (*current_ptr_to_next == rp) {
      *current_ptr_to_next = rp->p_vmrequest.nextrequestor;
      break;
    }
    current_ptr_to_next = &(*current_ptr_to_next)->p_vmrequest.nextrequestor;
  }

  RTS_UNSET(rp, RTS_VMREQUEST);
}

/*===========================================================================*
 *			         clear_ipc				     *
 *===========================================================================*/
static void clear_ipc(
  struct proc *rc
)
{
  if (RTS_ISSET(rc, RTS_SENDING)) {
      int target_proc_id;
      struct proc *target_proc_ptr;

      okendpt(rc->p_sendto_e, &target_proc_id);
      target_proc_ptr = proc_addr(target_proc_id);

      if (target_proc_ptr != NULL) {
          struct proc **current_q_ptr = &target_proc_ptr->p_caller_q;
          while (*current_q_ptr != NULL) {
              if (*current_q_ptr == rc) {
                  *current_q_ptr = (*current_q_ptr)->p_q_link;
#if DEBUG_ENABLE_IPC_WARNINGS
	          printf("endpoint %d / %s removed from queue at %d\n",
	              rc->p_endpoint, rc->p_name, rc->p_sendto_e);
#endif
                  break;
              }
              current_q_ptr = &(*current_q_ptr)->p_q_link;
          }
      }
      RTS_UNSET(rc, RTS_SENDING);
  }
  RTS_UNSET(rc, RTS_RECEIVING);
}

/*===========================================================================*
 *			         clear_endpoint				     *
 *===========================================================================*/
void clear_endpoint(struct proc * rc)
{
  if(isemptyp(rc)) panic("clear_proc: empty process: %d",  rc->p_endpoint);

#if DEBUG_IPC_HOOK
  hook_ipc_clear(rc);
#endif

  RTS_SET(rc, RTS_NO_ENDPOINT);
  if (priv(rc)->s_flags & SYS_PROC)
  {
	priv(rc)->s_asynsize= 0;
  }

  clear_ipc(rc);

  clear_ipc_refs(rc, EDEADSRCDST);

  clear_memreq(rc);
}

/*===========================================================================*
 *			       clear_ipc_refs				     *
 *===========================================================================*/
void clear_ipc_refs(
  struct proc *rc,
  int caller_ret
)
{
  struct proc *rp;
  int src_id;

  while ((src_id = has_pending_asend(rc, ANY)) != NULL_PRIV_ID)
      cancel_async(proc_addr(id_to_nr(src_id)), rc);

  for (rp = BEG_PROC_ADDR; rp < END_PROC_ADDR; rp++) {
      if(isemptyp(rp))
	continue;

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
    assert(!RTS_ISSET(caller, RTS_SLOT_FREE));
    assert(!RTS_ISSET(caller, RTS_VMREQUEST));
    assert(caller->p_vmrequest.saved.reqmsg.m_source == caller->p_endpoint);

    message *req_msg = &caller->p_vmrequest.saved.reqmsg;
    int result;

    result = kernel_call_dispatch(caller, req_msg);
    caller->p_misc_flags &= ~MF_KCALL_RESUME;
    kernel_call_finish(caller, req_msg, result);
}

/*===========================================================================*
 *                               sched_proc                                  *
 *===========================================================================*/
int sched_proc(struct proc *p, int priority, int quantum, int cpu, int niced)
{
	if (priority != -1 && (priority < TASK_Q || priority > NR_SCHED_QUEUES)) {
		return EINVAL;
	}

	if (quantum != -1 && quantum < 1) {
		return EINVAL;
	}

#ifdef CONFIG_SMP
	if (cpu != -1) {
		if (cpu < 0 || (unsigned int)cpu >= ncpus) {
			return EINVAL;
		}
		if (!cpu_is_ready(cpu)) {
			return EBADCPU;
		}
	}
#endif

	if (proc_is_runnable(p)) {
#ifdef CONFIG_SMP
		if (p->p_cpu != cpuid && cpu != -1 && cpu != p->p_cpu) {
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

	int num_elements = length / sizeof(ipc_filter_el_t);
	if (num_elements <= 0 || num_elements > IPCF_MAX_ELEMENTS) {
		return E2BIG;
	}

	ipc_filter_t *ipcf;
	IPCF_POOL_ALLOCATE_SLOT(type, &ipcf);
	if (ipcf == NULL) {
		return ENOMEM;
	}

	ipcf->num_elements = num_elements;
	ipcf->next = NULL;

	int r = data_copy(rp->p_endpoint, address, KERNEL, (vir_bytes)ipcf->elements, length);
	if (r == OK) {
		r = check_ipc_filter(ipcf, 1 /*fill_flags*/);
	}

	if (r != OK) {
		IPCF_POOL_FREE_SLOT(ipcf);
		return r;
	}

	ipc_filter_t **current_ipcfp = &priv(rp)->s_ipcf;
	while (*current_ipcfp != NULL) {
		current_ipcfp = &(*current_ipcfp)->next;
	}
	*current_ipcfp = ipcf;

	return OK;
}

/*===========================================================================*
 *				clear_ipc_filters			     *
 *===========================================================================*/
void clear_ipc_filters(struct proc *rp)
{
	ipc_filter_t *ipcf_current;
	ipc_filter_t *ipcf_next;

	ipcf_current = priv(rp)->s_ipcf;

	while (ipcf_current != NULL) {
		ipcf_next = ipcf_current->next;
		IPCF_POOL_FREE_SLOT(ipcf_current);
		ipcf_current = ipcf_next;
	}

	priv(rp)->s_ipcf = NULL;

	if (rp->p_endpoint == VM_PROC_NR && vmrequest != NULL) {
		if (send_sig(VM_PROC_NR, SIGKMEM) != OK) {
			panic("send_sig to VM_PROC_NR failed after clearing IPC filters");
		}
	}
}

/*===========================================================================*
 *				check_ipc_filter			     *
 *===========================================================================*/
int check_ipc_filter(ipc_filter_t *ipcf, const int fill_flags)
{
    if (ipcf == NULL) {
        return OK;
    }

    int accumulated_flags = 0;
    const int num_elements = ipcf->num_elements;

    for (int i = 0; i < num_elements; ++i) {
        ipc_filter_el_t *ipcf_el = &ipcf->elements[i];

        if (!IPCF_EL_CHECK(ipcf_el)) {
            return EINVAL;
        }
        accumulated_flags |= ipcf_el->flags;
    }

    if (fill_flags) {
        ipcf->flags = accumulated_flags;
    } else if (ipcf->flags != accumulated_flags) {
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
	int i, r;
	ipc_filter_t *ipcf_head, *current_ipcf;
	ipc_filter_el_t *ipcf_el;
	message m_buff;
	int allow;
	int need_mtype;

	ipcf_head = priv(rp)->s_ipcf;
	if (ipcf_head == NULL) {
		return 1;
	}

	need_mtype = 0;
#ifdef DEBUG_DUMPIPCF
	need_mtype = 1;
#else
	current_ipcf = ipcf_head;
	while (current_ipcf != NULL) {
		if (current_ipcf->flags & IPCF_MATCH_M_TYPE) {
			need_mtype = 1;
			break;
		}
		current_ipcf = current_ipcf->next;
	}
#endif

	if (m_src_p == NULL) {
		assert(m_src_v != 0);

		memset(&m_buff, 0, sizeof(m_buff));

		if (need_mtype) {
			r = data_copy(src_e,
			    m_src_v + offsetof(message, m_type), KERNEL,
			    (vir_bytes)&m_buff.m_type, sizeof(m_buff.m_type));
			if (r != OK) {
				return 1;
			}
		}
		m_src_p = &m_buff;
	}

	m_src_p->m_source = src_e;

	current_ipcf = ipcf_head;

	allow = (current_ipcf->type == IPCF_BLACKLIST);

	while (current_ipcf != NULL) {
		if ((current_ipcf->type == IPCF_WHITELIST && !allow) ||
		    (current_ipcf->type == IPCF_BLACKLIST && allow)) {

			for (i = 0; i < current_ipcf->num_elements; i++) {
				ipcf_el = &current_ipcf->elements[i];
				if (IPCF_EL_MATCH(ipcf_el, m_src_p)) {
					allow = (current_ipcf->type == IPCF_WHITELIST);
					break;
				}
			}
		}
		current_ipcf = current_ipcf->next;
	}

#ifdef DEBUG_DUMPIPCF
	printmsg(m_src_p, proc_addr(_ENDPOINT_P(src_e)), rp, allow ? '+' : '-',
	    1);
#endif

	return allow;
}

/*===========================================================================*
 *			  allow_ipc_filtered_memreq			     *
 *===========================================================================*/
int allow_ipc_filtered_memreq(struct proc *src_rp, struct proc *dst_rp)
{
	struct proc *vmp = proc_addr(VM_PROC_NR);

	if (priv(vmp)->s_ipcf == NULL) {
		return TRUE;
	}

	message m_buf;
	m_buf.m_type = NOTIFY_MESSAGE;
	return allow_ipc_filtered_msg(vmp, SYSTEM, 0, &m_buf);
}

/*===========================================================================*
 *                             priv_add_irq                                  *
 *===========================================================================*/
int priv_add_irq(struct proc *rp, int irq)
{
    struct priv *priv = priv(rp);

    priv->s_flags |= CHECK_IRQ;

    for (int i = 0; i < priv->s_nr_irq; i++) {
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
    if (rp == NULL) {
        return EFAULT;
    }
    if (ior == NULL) {
        return EFAULT;
    }

    struct priv *priv_data = priv(rp);
    if (priv_data == NULL) {
        return ENOENT;
    }

    priv_data->s_flags |= CHECK_IO_PORT;

    for (int i = 0; i < priv_data->s_nr_io_range; i++) {
        if (priv_data->s_io_tab[i].ior_base == ior->ior_base &&
            priv_data->s_io_tab[i].ior_limit == ior->ior_limit) {
            return OK;
        }
    }

    if (priv_data->s_nr_io_range >= NR_IO_RANGE) {
        printf("do_privctl: %d already has %d i/o ranges.\n",
               rp->p_endpoint, priv_data->s_nr_io_range);
        return ENOMEM;
    }

    priv_data->s_io_tab[priv_data->s_nr_io_range] = *ior;
    priv_data->s_nr_io_range++;

    return OK;
}

/*===========================================================================*
 *                             priv_add_mem                                  *
 *===========================================================================*/
int priv_add_mem(struct proc *rp, struct minix_mem_range *memr)
{
        struct priv *priv_ptr = priv(rp);
        int i;

	priv_ptr->s_flags |= CHECK_MEM;

	for (i = 0; i < priv_ptr->s_nr_mem_range; i++) {
		if (priv_ptr->s_mem_tab[i].mr_base == memr->mr_base &&
		    priv_ptr->s_mem_tab[i].mr_limit == memr->mr_limit) {
			return OK;
		}
	}

	if (priv_ptr->s_nr_mem_range >= NR_MEM_RANGE) {
		return ENOMEM;
	}

	priv_ptr->s_mem_tab[priv_ptr->s_nr_mem_range] = *memr;
	priv_ptr->s_nr_mem_range++;

	return OK;
}

