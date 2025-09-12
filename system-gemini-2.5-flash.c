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

  /* 1. Validate call number range. */
  if (call_nr < 0 || call_nr >= NR_SYS_CALLS) {
    printf("SYSTEM: illegal request %d from %d.\n", call_nr, msg->m_source);
    return EBADREQUEST;
  }

  /* 2. Validate caller permissions for this specific kernel call. */
  if (!GET_BIT(priv(caller)->s_k_call_mask, call_nr)) {
    printf("SYSTEM: denied request %d from %d.\n", call_nr, msg->m_source);
    return ECALLDENIED;
  }

  /* 3. Dispatch the system call if a handler is registered. */
  if (call_vec[call_nr]) {
    return (*call_vec[call_nr])(caller, msg);
  } else {
    /* This path indicates a valid, permitted call_nr but no handler defined.
     * It suggests an inconsistency between NR_SYS_CALLS/s_k_call_mask and call_vec. */
    printf("Unused kernel call %d from %d\n", call_nr, caller->p_endpoint);
    return EBADREQUEST;
  }
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
  message msg;
  int dispatch_result;

  caller->p_delivermsg_vir = (vir_bytes) m_user;

  if (copy_msg_from_user(m_user, &msg) != 0) {
	  printf("WARNING wrong user pointer 0x%08x from process %s / %d\n",
			  m_user, caller->p_name, caller->p_endpoint);
	  cause_sig(proc_nr(caller), SIGSEGV);
	  return;
  }

  msg.m_source = caller->p_endpoint;
  dispatch_result = kernel_call_dispatch(caller, &msg);

  kbill_kcall = caller;

  kernel_call_finish(caller, &msg, dispatch_result);
}

/*===========================================================================*
 *				initialize				     *
 *===========================================================================*/
void system_init(void)
{
  struct priv *sp;
  int i;

  /* Initialize IRQ handler hooks. Mark all hooks available. */
  for (i=0; i<NR_IRQ_HOOKS; i++) {
      irq_hooks[i].proc_nr_e = NONE;
  }

  /* Initialize all alarm timers for all processes. */
  for (sp=BEG_PRIV_ADDR; sp < END_PRIV_ADDR; sp++) {
    tmr_inittimer(&(sp->s_alarm_timer));
  }

  /* Initialize the call vector to a safe default handler. Some system calls
   * may be disabled or nonexistant. Then explicitly map known calls to their
   * handler functions. This is done with a macro that gives a compile error
   * if an illegal call number is used. The ordering is not important here.
   */
  for (i=0; i<NR_SYS_CALLS; i++) {
      call_vec[i] = NULL;
  }

  /* Process management. */
  map(SYS_FORK, do_fork); 		/* a process forked a new process */
  map(SYS_EXEC, do_exec);		/* update process after execute */
  map(SYS_CLEAR, do_clear);		/* clean up after process exit */
  map(SYS_EXIT, do_exit);		/* a system process wants to exit */
  map(SYS_PRIVCTL, do_privctl);		/* system privileges control */
  map(SYS_TRACE, do_trace);		/* request a trace operation */
  map(SYS_SETGRANT, do_setgrant);	/* get/set own parameters */
  map(SYS_RUNCTL, do_runctl);		/* set/clear stop flag of a process */
  map(SYS_UPDATE, do_update);		/* update a process into another */
  map(SYS_STATECTL, do_statectl);	/* let a process control its state */

  /* Signal handling. */
  map(SYS_KILL, do_kill); 		/* cause a process to be signaled */
  map(SYS_GETKSIG, do_getksig);		/* signal manager checks for signals */
  map(SYS_ENDKSIG, do_endksig);		/* signal manager finished signal */
  map(SYS_SIGSEND, do_sigsend);		/* start POSIX-style signal */
  map(SYS_SIGRETURN, do_sigreturn);	/* return from POSIX-style signal */

  /* Device I/O. */
  map(SYS_IRQCTL, do_irqctl);  		/* interrupt control operations */
#if defined(__i386__)
  map(SYS_DEVIO, do_devio);   		/* inb, inw, inl, outb, outw, outl */
  map(SYS_VDEVIO, do_vdevio);  		/* vector with devio requests */
#endif

  /* Memory management. */
  map(SYS_MEMSET, do_memset);		/* write char to memory area */
  map(SYS_VMCTL, do_vmctl);		/* various VM process settings */

  /* Copying. */
  map(SYS_UMAP, do_umap);		/* map virtual to physical address */
  map(SYS_UMAP_REMOTE, do_umap_remote);	/* do_umap for non-caller process */
  map(SYS_VUMAP, do_vumap);		/* vectored virtual to physical map */
  map(SYS_VIRCOPY, do_vircopy); 	/* use pure virtual addressing */
  map(SYS_PHYSCOPY, do_copy);	 	/* use physical addressing */
  map(SYS_SAFECOPYFROM, do_safecopy_from);/* copy with pre-granted permission */
  map(SYS_SAFECOPYTO, do_safecopy_to);	/* copy with pre-granted permission */
  map(SYS_VSAFECOPY, do_vsafecopy);	/* vectored safecopy */

  /* safe memset */
  map(SYS_SAFEMEMSET, do_safememset);	/* safememset */

  /* Clock functionality. */
  map(SYS_TIMES, do_times);		/* get uptime and process times */
  map(SYS_SETALARM, do_setalarm);	/* schedule a synchronous alarm */
  map(SYS_STIME, do_stime);		/* set the boottime */
  map(SYS_SETTIME, do_settime);		/* set the system time (realtime) */
  map(SYS_VTIMER, do_vtimer);		/* set or retrieve a virtual timer */

  /* System control. */
  map(SYS_ABORT, do_abort);		/* abort MINIX */
  map(SYS_GETINFO, do_getinfo); 	/* request system information */
  map(SYS_DIAGCTL, do_diagctl);		/* diagnostics-related functionality */

  /* Profiling. */
  map(SYS_SPROF, do_sprofile);         /* start/stop statistical profiling */

  /* arm-specific. */
#if defined(__arm__)
  map(SYS_PADCONF, do_padconf);		/* configure pinmux */
#endif

  /* i386-specific. */
#if defined(__i386__)
  map(SYS_READBIOS, do_readbios);	/* read from BIOS locations */
  map(SYS_IOPENABLE, do_iopenable); 	/* Enable I/O */
  map(SYS_SDEVIO, do_sdevio);		/* phys_insb, _insw, _outsb, _outsw */
#endif

  /* Machine state switching. */
  map(SYS_SETMCONTEXT, do_setmcontext); /* set machine context */
  map(SYS_GETMCONTEXT, do_getmcontext); /* get machine context */

  /* Scheduling */
  map(SYS_SCHEDULE, do_schedule);	/* reschedule a process */
  map(SYS_SCHEDCTL, do_schedctl);	/* change process scheduler */

}
/*===========================================================================*
 *				get_priv				     *
 *===========================================================================*/
int get_priv(
  struct proc *rc,
  const int priv_id
)
{
  struct priv *sp = NULL;

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

  struct priv *process_priv = priv(rp);
  if (process_priv == NULL) {
    return;
  }

  struct priv *target_priv = NULL;
  if (id_to_nr(id) != NONE) {
    target_priv = priv_addr(id);
  }

  if (target_priv == NULL || priv_id(rp) == id) {
	unset_sys_bit(process_priv->s_ipc_to, id);
	return;
  }

  set_sys_bit(process_priv->s_ipc_to, id);

  if (target_priv->s_trap_mask & ~((1 << RECEIVE))) {
      set_sys_bit(target_priv->s_ipc_to, priv_id(rp));
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

  if (id < 0) {
    return;
  }

  struct priv *priv_rp = priv(rp);
  if (priv_rp == NULL) {
    return;
  }

  struct priv *priv_id_ptr = priv_addr(id);
  if (priv_id_ptr == NULL) {
    return;
  }

  int rp_id = priv_id(rp);
  if (rp_id < 0) {
    return;
  }

  unset_sys_bit(priv_rp->s_ipc_to, id);

  unset_sys_bit(priv_id_ptr->s_ipc_to, rp_id);
}

/*===========================================================================*
 *			      fill_sendto_mask				     *
 *===========================================================================*/
void fill_sendto_mask(const struct proc *rp, const sys_map_t *map)
{
  int i;

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
  struct priv *priv_data;
  int proc_nr;

  if (!isokendpt(ep, &proc_nr) || isemptyn(proc_nr)) {
    return EINVAL;
  }

  rp = proc_addr(proc_nr);
  if (rp == NULL) {
    return ENOENT;
  }

  priv_data = priv(rp);
  if (priv_data == NULL) {
    return ENOENT;
  }

  sigaddset(&priv_data->s_sig_pending, sig_nr);
  mini_notify(proc_addr(SYSTEM), rp->p_endpoint);

  return OK;
}

/*===========================================================================*
 *				cause_sig				     *
 *===========================================================================*/
void cause_sig(proc_nr_t proc_nr, int sig_nr)
{
  struct proc *rp;
  endpoint_t sig_mgr;

  rp = proc_addr(proc_nr);
  /* Assuming proc_addr always returns a valid pointer for an active proc_nr. */

  sig_mgr = priv(rp)->s_sig_mgr;
  if (sig_mgr == SELF) {
    sig_mgr = rp->p_endpoint;
  }

  /* If the target process is its own signal manager. */
  if (rp->p_endpoint == sig_mgr) {
    if (SIGS_IS_LETHAL(sig_nr)) {
      /* If the signal is lethal, check for a backup signal manager. */
      endpoint_t backup_sig_mgr = priv(rp)->s_bak_sig_mgr;
      int backup_sig_mgr_proc_nr;

      if (backup_sig_mgr != NONE && isokendpt(backup_sig_mgr, &backup_sig_mgr_proc_nr)) {
        struct proc *new_sig_mgr_rp = proc_addr(backup_sig_mgr_proc_nr);
        /* Assuming new_sig_mgr_rp is valid if isokendpt succeeded. */

        priv(rp)->s_sig_mgr = backup_sig_mgr;
        priv(rp)->s_bak_sig_mgr = NONE;
        RTS_UNSET(new_sig_mgr_rp, RTS_NO_PRIV);

        /* Try again with the new signal manager. */
        cause_sig(proc_nr, sig_nr);
        return;
      }

      /* No backup signal manager or backup invalid. Time to panic. */
      proc_stacktrace(rp);
      panic("cause_sig: sig manager %d gets lethal signal %d for itself",
            rp->p_endpoint, sig_nr);
    }

    /* Add the signal to the process's pending signals if not lethal or backup failed. */
    sigaddset(&priv(rp)->s_sig_pending, sig_nr);
    if (OK != send_sig(rp->p_endpoint, SIGKSIGSM)) {
      panic("send_sig failed");
    }
    return;
  }

  /* Handle signals for processes managed by an external signal manager. */
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
  struct proc *p;
  endpoint_t ep;

  for (privp = BEG_PRIV_ADDR; privp < END_PRIV_ADDR; privp++) {
    if (privp->s_proc_nr != NONE && privp->s_diag_sig) {
      p = proc_addr(privp->s_proc_nr);

      if (p == NULL) {
        continue;
      }

      ep = p->p_endpoint;

      if (send_sig(ep, SIGKMESS) != OK) {
        continue;
      }
    }
  }
}

/*===========================================================================*
 *			         clear_memreq				     *
 *===========================================================================*/
static void clear_memreq(struct proc *rp)
{
  struct proc **rpp;

  if (!RTS_ISSET(rp, RTS_VMREQUEST)) {
    return;
  }

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
static void clear_ipc(
  struct proc *rc
)
{
  struct proc **xpp;

  if (RTS_ISSET(rc, RTS_SENDING)) {
      int target_proc_id;
      struct proc *target_proc_ptr;

      okendpt(rc->p_sendto_e, &target_proc_id);

      target_proc_ptr = proc_addr(target_proc_id);

      if (target_proc_ptr != NULL) {
          xpp = &target_proc_ptr->p_caller_q;
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
  if(isemptyp(rc)) panic("clear_endpoint: empty process: %d",  rc->p_endpoint);

#if DEBUG_IPC_HOOK
  hook_ipc_clear(rc);
#endif

  RTS_SET(rc, RTS_NO_ENDPOINT);
  if (priv(rc)->s_flags & SYS_PROC)
  {
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
	int result;
	struct message *reqmsg = &caller->p_vmrequest.saved.reqmsg;

	assert(!RTS_ISSET(caller, RTS_SLOT_FREE));
	assert(!RTS_ISSET(caller, RTS_VMREQUEST));

	assert(reqmsg->m_source == caller->p_endpoint);

	result = kernel_call_dispatch(caller, reqmsg);
	caller->p_misc_flags &= ~MF_KCALL_RESUME;
	kernel_call_finish(caller, reqmsg, result);
}

/*===========================================================================*
 *                               sched_proc                                  *
 *===========================================================================*/
int sched_proc(struct proc *p, int priority, int quantum, int cpu, int niced)
{
	if (p == NULL) {
		return EINVAL;
	}

	// Validate priority parameter: must be within allowed range or -1 (no change).
	if (priority != -1 && (priority < TASK_Q || priority > NR_SCHED_QUEUES)) {
		return EINVAL;
	}

	// Validate quantum parameter: must be at least 1 or -1 (no change).
	if (quantum != -1 && quantum < 1) {
		return EINVAL;
	}

#ifdef CONFIG_SMP
	// Validate CPU parameter: must be within [0, ncpus-1] or -1 (no change).
	if (cpu != -1) {
		if (cpu < 0 || (unsigned)cpu >= ncpus) {
			return EINVAL;
		}
		// Check if the target CPU is ready.
		if (!cpu_is_ready(cpu)) {
			return EBADCPU;
		}
	}
#endif

	// Determine if the process is currently runnable.
	// If it is, we temporarily dequeue it before modifying its scheduling parameters
	// to prevent race conditions and ensure it's re-enqueued correctly.
	bool was_runnable = proc_is_runnable(p);

	if (was_runnable) {
#ifdef CONFIG_SMP
		// Handle process migration if a new CPU is specified and differs from its current CPU,
		// and the process is currently running on a different CPU than the current one (cpuid).
		// This specific condition for migration is preserved from the original code.
		if (p->p_cpu != cpuid && cpu != -1 && cpu != p->p_cpu) {
			smp_schedule_migrate_proc(p, cpu);
		}
#endif
		// Mark the process as temporarily not eligible for scheduling.
		// This flag will be cleared at the end of the function to allow re-enqueuing.
		RTS_SET(p, RTS_NO_QUANTUM);
	}

	// Update process scheduling parameters based on provided values.
	// A value of -1 indicates no change for that parameter.
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

	// Update the niceness flag.
	if (niced) {
		p->p_misc_flags |= MF_NICED;
	} else {
		p->p_misc_flags &= ~MF_NICED;
	}

	// Clear the RTS_NO_QUANTUM flag.
	// This action is unconditional, as in the original code, implying that
	// the scheduler will re-evaluate the process's state and potentially
	// re-enqueue it into the appropriate run queue based on its new parameters.
	RTS_UNSET(p, RTS_NO_QUANTUM);

	return OK;
}

/*===========================================================================*
 *				add_ipc_filter				     *
 *===========================================================================*/
int add_ipc_filter(struct proc *rp, int type, vir_bytes address, size_t length)
{
    int num_elements;
    int r;
    ipc_filter_t *ipcf;
    ipc_filter_t **ipcfp;

    if (type != IPCF_BLACKLIST && type != IPCF_WHITELIST) {
        return EINVAL;
    }

    if (length == 0 || length % sizeof(ipc_filter_el_t) != 0) {
        return EINVAL;
    }

    num_elements = length / sizeof(ipc_filter_el_t);
    if (num_elements > IPCF_MAX_ELEMENTS) {
        return E2BIG;
    }

    IPCF_POOL_ALLOCATE_SLOT(type, &ipcf);
    if (ipcf == NULL) {
        return ENOMEM;
    }

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

    ipcfp = &priv(rp)->s_ipcf;
    while (*ipcfp != NULL) {
        ipcfp = &(*ipcfp)->next;
    }
    *ipcfp = ipcf;

    return OK;
}

/*===========================================================================*
 *				clear_ipc_filters			     *
 *===========================================================================*/
void clear_ipc_filters(struct proc *rp)
{
	ipc_filter_t *ipcf_node;

	ipcf_node = priv(rp)->s_ipcf;
	while (ipcf_node != NULL) {
		ipc_filter_t *next_node = ipcf_node->next;
		IPCF_POOL_FREE_SLOT(ipcf_node);
		ipcf_node = next_node;
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
    if (ipcf == NULL) {
        return OK;
    }

    if (ipcf->num_elements < 0) {
        return EINVAL;
    }

    int accumulated_flags = 0;
    int num_elements = ipcf->num_elements;

    for (size_t i = 0; i < (size_t)num_elements; ++i) {
        const ipc_filter_el_t *current_element = &ipcf->elements[i];
        if (!IPCF_EL_CHECK(current_element)) {
            return EINVAL;
        }
        accumulated_flags |= current_element->flags;
    }

    if (fill_flags) {
        ipcf->flags = accumulated_flags;
    } else {
        if (ipcf->flags != accumulated_flags) {
            return EINVAL;
        }
    }

    return OK;
}

/*===========================================================================*
 *				allow_ipc_filtered_msg			     *
 *===========================================================================*/
int allow_ipc_filtered_msg(struct proc *rp, endpoint_t src_e,
	vir_bytes m_src_v, message *m_src_p)
{
	ipc_filter_t *ipcf_list_head;
	ipc_filter_t *current_filter;
	ipc_filter_el_t *filter_element;
	message m_buffer;
	int result_code;
	int num_elements;
	int get_message_type = FALSE;
	int is_allowed;

	ipcf_list_head = priv(rp)->s_ipcf;

	if (ipcf_list_head == NULL) {
		return TRUE; /* No IPC filters, always allow */
	}

	/* Determine if the message type needs to be copied. */
	/* Iterate through the filter list to see if any filter checks m_type. */
	current_filter = ipcf_list_head;
	while (current_filter != NULL) {
#if DEBUG_DUMPIPCF
		get_message_type = TRUE; /* If debug is on, always copy the type */
		break;
#else
		if (current_filter->flags & IPCF_MATCH_M_TYPE) {
			get_message_type = TRUE;
			break;
		}
#endif
		current_filter = current_filter->next;
	}

	/* If m_src_p is NULL, the message data is in the process's address space (m_src_v). */
	/* We need to copy at least the m_type if any filter requires it. */
	if (m_src_p == NULL) {
		assert(m_src_v != 0);

		if (get_message_type) {
			result_code = data_copy(src_e,
			    m_src_v + offsetof(message, m_type), KERNEL,
			    (vir_bytes)&m_buffer.m_type, sizeof(m_buffer.m_type));
			if (result_code != OK) {
				/* Preserving original behavior: allow message if m_type copy fails. */
				return TRUE;
			}
		}
		m_src_p = &m_buffer; /* Point to our local buffer for filtering */
	}

	/* Ensure m_source is set correctly in the message being evaluated. */
	m_src_p->m_source = src_e;

	/* Initialize the 'is_allowed' state based on the first filter's type. */
	is_allowed = (ipcf_list_head->type == IPCF_BLACKLIST);

	/* Iterate through all IPC filters to apply rules. */
	current_filter = ipcf_list_head;
	while (current_filter != NULL) {
		/* Only evaluate a filter if it has the potential to change the current 'is_allowed' state. */
		/* If current_filter is WHITELIST and we are currently denying (!is_allowed), */
		/* or if current_filter is BLACKLIST and we are currently allowing (is_allowed). */
		if ((current_filter->type == IPCF_WHITELIST && !is_allowed) ||
		    (current_filter->type == IPCF_BLACKLIST && is_allowed)) {

			num_elements = current_filter->num_elements;
			for (int i = 0; i < num_elements; i++) {
				filter_element = &current_filter->elements[i];

				if (IPCF_EL_MATCH(filter_element, m_src_p)) {
					/* A match was found, update 'is_allowed' based on this filter's type. */
					is_allowed = (current_filter->type == IPCF_WHITELIST);
					break; /* Matched an element, no need to check others in THIS filter */
				}
			}
		}
		current_filter = current_filter->next; /* Move to the next filter in the chain */
	}

#if DEBUG_DUMPIPCF
	printmsg(m_src_p, proc_addr(_ENDPOINT_P(src_e)), rp, is_allowed ? '+' : '-', TRUE /*printparams*/);
#endif

	return is_allowed;
}

/*===========================================================================*
 *			  allow_ipc_filtered_memreq			     *
 *===========================================================================*/
int allow_ipc_filtered_memreq(struct proc *src_rp, struct proc *dst_rp)
{
	struct proc *vmp;
	message m_notification;

	vmp = proc_addr(VM_PROC_NR);
	if (vmp == NULL) {
		return FALSE;
	}

	if (priv(vmp)->s_ipcf == NULL) {
		return TRUE;
	}

	m_notification.m_type = NOTIFY_MESSAGE;
	if (!allow_ipc_filtered_msg(vmp, SYSTEM, 0, &m_notification)) {
		return FALSE;
	}

	return TRUE;
}

/*===========================================================================*
 *                             priv_add_irq                                  *
 *===========================================================================*/
int priv_add_irq(struct proc *rp, int irq)
{
    struct priv *proc_priv = priv(rp);

    proc_priv->s_flags |= CHECK_IRQ;

    for (int i = 0; i < proc_priv->s_nr_irq; ++i) {
        if (proc_priv->s_irq_tab[i] == irq) {
            return OK;
        }
    }

    if (proc_priv->s_nr_irq >= NR_IRQ) {
        printf("do_privctl: Process %d already has %d IRQs. Maximum capacity of %d reached.\n",
               rp->p_endpoint, proc_priv->s_nr_irq, NR_IRQ);
        return ENOMEM;
    }

    proc_priv->s_irq_tab[proc_priv->s_nr_irq] = irq;
    proc_priv->s_nr_irq++;

    return OK;
}

/*===========================================================================*
 *                             priv_add_io                                   *
 *===========================================================================*/
int priv_add_io(struct proc *rp, const struct io_range *ior)
{
    if (rp == NULL || ior == NULL) {
        return EINVAL;
    }

    struct priv *p_priv = priv(rp);

    if (p_priv == NULL) {
        return ENXIO;
    }

    p_priv->s_flags |= CHECK_IO_PORT;

    for (int i = 0; i < p_priv->s_nr_io_range; ++i) {
        if (p_priv->s_io_tab[i].ior_base == ior->ior_base &&
            p_priv->s_io_tab[i].ior_limit == ior->ior_limit) {
            return OK;
        }
    }

    if (p_priv->s_nr_io_range >= NR_IO_RANGE) {
        return ENOMEM;
    }

    p_priv->s_io_tab[p_priv->s_nr_io_range] = *ior;
    p_priv->s_nr_io_range++;

    return OK;
}

/*===========================================================================*
 *                             priv_add_mem                                  *
 *===========================================================================*/
int priv_add_mem(struct proc *rp, struct minix_mem_range *memr)
{
        struct priv *priv = priv(rp);
        int i;

	priv->s_flags |= CHECK_MEM;

	for (i = 0; i < priv->s_nr_mem_range; i++) {
		if (priv->s_mem_tab[i].mr_base == memr->mr_base &&
			priv->s_mem_tab[i].mr_limit == memr->mr_limit)
			return OK;
	}

	/* At this point, 'i' holds the value of priv->s_nr_mem_range,
	 * representing both the current count and the next available index. */
	if (i >= NR_MEM_RANGE) {
		printf("do_privctl: %d already has %d mem ranges.\n",
			rp->p_endpoint, i);
		return ENOMEM;
	}
	priv->s_mem_tab[i]= *memr;
	priv->s_nr_mem_range++;
	return OK;
}

