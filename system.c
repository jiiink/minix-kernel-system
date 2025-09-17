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

static void handle_vm_suspend(struct proc *caller, message *msg)
{
    assert(RTS_ISSET(caller, RTS_VMREQUEST));
    assert(caller->p_vmrequest.type == VMSTYPE_KERNELCALL);
    caller->p_vmrequest.saved.reqmsg = *msg;
    caller->p_misc_flags |= MF_KCALL_RESUME;
}

static void clear_request_message(struct proc *caller)
{
    caller->p_vmrequest.saved.reqmsg.m_source = NONE;
}

static void prepare_result_message(message *msg, int result)
{
    msg->m_source = SYSTEM;
    msg->m_type = result;
}

static void handle_copy_error(struct proc *caller)
{
    printf("WARNING wrong user pointer 0x%08x from process %s / %d\n",
           caller->p_delivermsg_vir,
           caller->p_name,
           caller->p_endpoint);
    cause_sig(proc_nr(caller), SIGSEGV);
}

static void send_result_to_user(struct proc *caller, message *msg, int result)
{
    prepare_result_message(msg, result);
    
#if DEBUG_IPC_HOOK
    hook_ipc_msgkresult(msg, caller);
#endif
    
    if (copy_msg_to_user(msg, (message *)caller->p_delivermsg_vir)) {
        handle_copy_error(caller);
    }
}

static void kernel_call_finish(struct proc *caller, message *msg, int result)
{
    if (result == VMSUSPEND) {
        handle_vm_suspend(caller, msg);
        return;
    }
    
    clear_request_message(caller);
    
    if (result != EDONTREPLY) {
        send_result_to_user(caller, msg, result);
    }
}

static int validate_call_number(int call_nr, int source)
{
    if (call_nr < 0 || call_nr >= NR_SYS_CALLS) {
        printf("SYSTEM: illegal request %d from %d.\n", call_nr, source);
        return EBADREQUEST;
    }
    return OK;
}

static int check_call_permission(struct proc *caller, int call_nr, int source)
{
    if (!GET_BIT(priv(caller)->s_k_call_mask, call_nr)) {
        printf("SYSTEM: denied request %d from %d.\n", call_nr, source);
        return ECALLDENIED;
    }
    return OK;
}

static int execute_kernel_call(struct proc *caller, message *msg, int call_nr)
{
    if (call_vec[call_nr])
        return (*call_vec[call_nr])(caller, msg);
    
    printf("Unused kernel call %d from %d\n", call_nr, caller->p_endpoint);
    return EBADREQUEST;
}

static int kernel_call_dispatch(struct proc *caller, message *msg)
{
    int result;
    int call_nr;

#if DEBUG_IPC_HOOK
    hook_ipc_msgkcall(msg, caller);
#endif
    call_nr = msg->m_type - KERNEL_CALL;

    result = validate_call_number(call_nr, msg->m_source);
    if (result != OK)
        return result;

    result = check_call_permission(caller, call_nr, msg->m_source);
    if (result != OK)
        return result;

    return execute_kernel_call(caller, msg, call_nr);
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
    int result = OK;
    message msg;

    caller->p_delivermsg_vir = (vir_bytes) m_user;

    if (copy_msg_from_user(m_user, &msg) != 0) {
        handle_invalid_user_pointer(m_user, caller);
        return;
    }

    msg.m_source = caller->p_endpoint;
    result = kernel_call_dispatch(caller, &msg);
    kbill_kcall = caller;
    kernel_call_finish(caller, &msg, result);
}

void handle_invalid_user_pointer(message *m_user, struct proc *caller)
{
    printf("WARNING wrong user pointer 0x%08x from process %s / %d\n",
            m_user, caller->p_name, caller->p_endpoint);
    cause_sig(proc_nr(caller), SIGSEGV);
}

/*===========================================================================*
 *				initialize				     *
 *===========================================================================*/
void system_init(void)
{
  init_irq_hooks();
  init_alarm_timers();
  init_call_vector();
  register_system_calls();
}

static void init_irq_hooks(void)
{
  int i;
  for (i = 0; i < NR_IRQ_HOOKS; i++) {
      irq_hooks[i].proc_nr_e = NONE;
  }
}

static void init_alarm_timers(void)
{
  register struct priv *sp;
  for (sp = BEG_PRIV_ADDR; sp < END_PRIV_ADDR; sp++) {
    tmr_inittimer(&(sp->s_alarm_timer));
  }
}

static void init_call_vector(void)
{
  int i;
  for (i = 0; i < NR_SYS_CALLS; i++) {
      call_vec[i] = NULL;
  }
}

static void register_system_calls(void)
{
  register_process_management_calls();
  register_signal_handling_calls();
  register_device_io_calls();
  register_memory_management_calls();
  register_copying_calls();
  register_clock_calls();
  register_system_control_calls();
  register_profiling_calls();
  register_architecture_specific_calls();
  register_machine_state_calls();
  register_scheduling_calls();
}

static void register_process_management_calls(void)
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

static void register_signal_handling_calls(void)
{
  map(SYS_KILL, do_kill);
  map(SYS_GETKSIG, do_getksig);
  map(SYS_ENDKSIG, do_endksig);
  map(SYS_SIGSEND, do_sigsend);
  map(SYS_SIGRETURN, do_sigreturn);
}

static void register_device_io_calls(void)
{
  map(SYS_IRQCTL, do_irqctl);
#if defined(__i386__)
  map(SYS_DEVIO, do_devio);
  map(SYS_VDEVIO, do_vdevio);
#endif
}

static void register_memory_management_calls(void)
{
  map(SYS_MEMSET, do_memset);
  map(SYS_VMCTL, do_vmctl);
}

static void register_copying_calls(void)
{
  map(SYS_UMAP, do_umap);
  map(SYS_UMAP_REMOTE, do_umap_remote);
  map(SYS_VUMAP, do_vumap);
  map(SYS_VIRCOPY, do_vircopy);
  map(SYS_PHYSCOPY, do_copy);
  map(SYS_SAFECOPYFROM, do_safecopy_from);
  map(SYS_SAFECOPYTO, do_safecopy_to);
  map(SYS_VSAFECOPY, do_vsafecopy);
  map(SYS_SAFEMEMSET, do_safememset);
}

static void register_clock_calls(void)
{
  map(SYS_TIMES, do_times);
  map(SYS_SETALARM, do_setalarm);
  map(SYS_STIME, do_stime);
  map(SYS_SETTIME, do_settime);
  map(SYS_VTIMER, do_vtimer);
}

static void register_system_control_calls(void)
{
  map(SYS_ABORT, do_abort);
  map(SYS_GETINFO, do_getinfo);
  map(SYS_DIAGCTL, do_diagctl);
}

static void register_profiling_calls(void)
{
  map(SYS_SPROF, do_sprofile);
}

static void register_architecture_specific_calls(void)
{
#if defined(__arm__)
  map(SYS_PADCONF, do_padconf);
#endif

#if defined(__i386__)
  map(SYS_READBIOS, do_readbios);
  map(SYS_IOPENABLE, do_iopenable);
  map(SYS_SDEVIO, do_sdevio);
#endif
}

static void register_machine_state_calls(void)
{
  map(SYS_SETMCONTEXT, do_setmcontext);
  map(SYS_GETMCONTEXT, do_getmcontext);
}

static void register_scheduling_calls(void)
{
  map(SYS_SCHEDULE, do_schedule);
  map(SYS_SCHEDCTL, do_schedctl);
}
/*===========================================================================*
 *				get_priv				     *
 *===========================================================================*/
int get_priv(
  register struct proc *rc,
  int priv_id
)
{
  register struct priv *sp;

  if(priv_id == NULL_PRIV_ID) {
      sp = allocate_dynamic_priv();
      if (sp == NULL) return(ENOSPC);
  }
  else {
      sp = allocate_static_priv(priv_id);
      if (sp == NULL) return EINVAL;
      if (sp == (struct priv *)-1) return EBUSY;
  }
  
  assign_priv_to_process(rc, sp);
  return(OK);
}

static struct priv* allocate_dynamic_priv(void)
{
  register struct priv *sp;
  
  for (sp = BEG_DYN_PRIV_ADDR; sp < END_DYN_PRIV_ADDR; ++sp) {
      if (sp->s_proc_nr == NONE) return sp;
  }
  return NULL;
}

static struct priv* allocate_static_priv(int priv_id)
{
  if(!is_static_priv_id(priv_id)) {
      return NULL;
  }
  if(priv[priv_id].s_proc_nr != NONE) {
      return (struct priv *)-1;
  }
  return &priv[priv_id];
}

static void assign_priv_to_process(struct proc *rc, struct priv *sp)
{
  rc->p_priv = sp;
  rc->p_priv->s_proc_nr = proc_nr(rc);
}

/*===========================================================================*
 *				set_sendto_bit				     *
 *===========================================================================*/
void set_sendto_bit(const struct proc *rp, int id)
{
  if (id_to_nr(id) == NONE || priv_id(rp) == id) {
    unset_sys_bit(priv(rp)->s_ipc_to, id);
    return;
  }

  set_sys_bit(priv(rp)->s_ipc_to, id);

  if (priv_addr(id)->s_trap_mask & ~((1 << RECEIVE)))
    set_sys_bit(priv_addr(id)->s_ipc_to, priv_id(rp));
}

/*===========================================================================*
 *				unset_sendto_bit			     *
 *===========================================================================*/
void unset_sendto_bit(const struct proc *rp, int id)
{
  unset_sys_bit(priv(rp)->s_ipc_to, id);
  unset_sys_bit(priv_addr(id)->s_ipc_to, priv_id(rp));
}

/*===========================================================================*
 *			      fill_sendto_mask				     *
 *===========================================================================*/
void fill_sendto_mask(const struct proc *rp, sys_map_t *map)
{
  int i;

  for (i = 0; i < NR_SYS_PROCS; i++) {
    if (get_sys_bit(*map, i))
      set_sendto_bit(rp, i);
    else
      unset_sendto_bit(rp, i);
  }
}

/*===========================================================================*
 *				send_sig				     *
 *===========================================================================*/
int send_sig(endpoint_t ep, int sig_nr)
{
  register struct proc *rp;
  struct priv *priv;
  int proc_nr;

  if(!isokendpt(ep, &proc_nr) || isemptyn(proc_nr))
	return EINVAL;

  rp = proc_addr(proc_nr);
  priv = priv(rp);
  if(!priv) return ENOENT;
  sigaddset(&priv->s_sig_pending, sig_nr);
  mini_notify(proc_addr(SYSTEM), rp->p_endpoint);

  return OK;
}

/*===========================================================================*
 *				cause_sig				     *
 *===========================================================================*/
void cause_sig(proc_nr_t proc_nr, int sig_nr)
{
  register struct proc *rp, *sig_mgr_rp;
  endpoint_t sig_mgr;
  int sig_mgr_proc_nr;

  rp = proc_addr(proc_nr);
  sig_mgr = priv(rp)->s_sig_mgr;
  if(sig_mgr == SELF) sig_mgr = rp->p_endpoint;

  if(rp->p_endpoint == sig_mgr) {
      handle_self_signal(rp, sig_nr, proc_nr);
      return;
  }

  process_signal_to_other(rp, sig_nr, sig_mgr);
}

static void handle_self_signal(struct proc *rp, int sig_nr, proc_nr_t proc_nr)
{
  if(SIGS_IS_LETHAL(sig_nr)) {
      if(try_backup_signal_manager(rp, sig_nr, proc_nr)) {
          return;
      }
      proc_stacktrace(rp);
      panic("cause_sig: sig manager %d gets lethal signal %d for itself",
          rp->p_endpoint, sig_nr);
  }
  
  sigaddset(&priv(rp)->s_sig_pending, sig_nr);
  if(OK != send_sig(rp->p_endpoint, SIGKSIGSM))
      panic("send_sig failed");
}

static int try_backup_signal_manager(struct proc *rp, int sig_nr, proc_nr_t proc_nr)
{
  endpoint_t sig_mgr;
  int sig_mgr_proc_nr;
  struct proc *sig_mgr_rp;
  
  sig_mgr = priv(rp)->s_bak_sig_mgr;
  if(sig_mgr == NONE || !isokendpt(sig_mgr, &sig_mgr_proc_nr)) {
      return 0;
  }
  
  priv(rp)->s_sig_mgr = sig_mgr;
  priv(rp)->s_bak_sig_mgr = NONE;
  sig_mgr_rp = proc_addr(sig_mgr_proc_nr);
  RTS_UNSET(sig_mgr_rp, RTS_NO_PRIV);
  cause_sig(proc_nr, sig_nr);
  return 1;
}

static void process_signal_to_other(struct proc *rp, int sig_nr, endpoint_t sig_mgr)
{
  int s = sigismember(&rp->p_pending, sig_nr);
  
  if (s) {
      return;
  }
  
  sigaddset(&rp->p_pending, sig_nr);
  if (RTS_ISSET(rp, RTS_SIGNALED)) {
      return;
  }
  
  RTS_SET(rp, RTS_SIGNALED | RTS_SIG_PENDING);
  if(OK != send_sig(sig_mgr, SIGKSIG))
      panic("send_sig failed");
}

/*===========================================================================*
 *				sig_delay_done				     *
 *===========================================================================*/
void sig_delay_done(struct proc *rp)
{
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
        if (should_send_diagnostic_signal(privp)) {
            send_diagnostic_signal_to_process(privp);
        }
    }
}

static int should_send_diagnostic_signal(struct priv *privp)
{
    return privp->s_proc_nr != NONE && privp->s_diag_sig == TRUE;
}

static void send_diagnostic_signal_to_process(struct priv *privp)
{
    endpoint_t ep = proc_addr(privp->s_proc_nr)->p_endpoint;
    send_sig(ep, SIGKMESS);
}

/*===========================================================================*
 *			         clear_memreq				     *
 *===========================================================================*/
static void clear_memreq(struct proc *rp)
{
  if (!RTS_ISSET(rp, RTS_VMREQUEST))
    return;

  remove_from_vmrequest_list(rp);
  RTS_UNSET(rp, RTS_VMREQUEST);
}

static void remove_from_vmrequest_list(struct proc *rp)
{
  struct proc **rpp = &vmrequest;
  
  while (*rpp != NULL) {
    if (*rpp == rp) {
      *rpp = rp->p_vmrequest.nextrequestor;
      break;
    }
    rpp = &(*rpp)->p_vmrequest.nextrequestor;
  }
}

/*===========================================================================*
 *			         clear_ipc				     *
 *===========================================================================*/
static void remove_from_caller_queue(struct proc *rc, struct proc *target) {
    struct proc **xpp = &target->p_caller_q;
    
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

static void clear_sending_state(struct proc *rc) {
    int target_proc;
    
    if (!RTS_ISSET(rc, RTS_SENDING)) {
        return;
    }
    
    okendpt(rc->p_sendto_e, &target_proc);
    remove_from_caller_queue(rc, proc_addr(target_proc));
    RTS_UNSET(rc, RTS_SENDING);
}

static void clear_ipc(register struct proc *rc) {
    clear_sending_state(rc);
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
void clear_ipc_refs(register struct proc *rc, int caller_ret)
{
    cancel_pending_asends(rc);
    clear_all_process_references(rc, caller_ret);
}

static void cancel_pending_asends(struct proc *rc)
{
    int src_id;
    while ((src_id = has_pending_asend(rc, ANY)) != NULL_PRIV_ID) {
        cancel_async(proc_addr(id_to_nr(src_id)), rc);
    }
}

static void clear_all_process_references(struct proc *rc, int caller_ret)
{
    struct proc *rp;
    for (rp = BEG_PROC_ADDR; rp < END_PROC_ADDR; rp++) {
        if (!isemptyp(rp)) {
            clear_process_reference(rp, rc, caller_ret);
        }
    }
}

static void clear_process_reference(struct proc *rp, struct proc *rc, int caller_ret)
{
    unset_sys_bit(priv(rp)->s_notify_pending, priv(rc)->s_id);
    unset_sys_bit(priv(rp)->s_asyn_pending, priv(rc)->s_id);
    
    if (P_BLOCKEDON(rp) == rc->p_endpoint) {
        rp->p_reg.retreg = caller_ret;
        clear_ipc(rp);
    }
}

/*===========================================================================*
 *                              kernel_call_resume                           *
 *===========================================================================*/
void kernel_call_resume(struct proc *caller)
{
	int result;

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
#define INVALID_PRIORITY -1
#define INVALID_QUANTUM -1
#define INVALID_CPU -1

static int validate_priority(int priority)
{
	if (priority == INVALID_PRIORITY)
		return OK;
	if (priority < TASK_Q || priority > NR_SCHED_QUEUES)
		return EINVAL;
	return OK;
}

static int validate_quantum(int quantum)
{
	if (quantum == INVALID_QUANTUM)
		return OK;
	if (quantum < 1)
		return EINVAL;
	return OK;
}

#ifdef CONFIG_SMP
static int validate_cpu(int cpu)
{
	if (cpu == INVALID_CPU)
		return OK;
	if (cpu < 0 || (unsigned) cpu >= ncpus)
		return EINVAL;
	if (!cpu_is_ready(cpu))
		return EBADCPU;
	return OK;
}

static void handle_cpu_migration(struct proc *p, int cpu)
{
	if (cpu != INVALID_CPU && cpu != p->p_cpu && p->p_cpu != cpuid) {
		smp_schedule_migrate_proc(p, cpu);
	}
}
#endif

static int validate_parameters(int priority, int quantum, int cpu)
{
	int result;
	
	result = validate_priority(priority);
	if (result != OK)
		return result;
	
	result = validate_quantum(quantum);
	if (result != OK)
		return result;
	
#ifdef CONFIG_SMP
	result = validate_cpu(cpu);
	if (result != OK)
		return result;
#endif
	
	return OK;
}

static void prepare_runnable_process(struct proc *p, int cpu)
{
	if (!proc_is_runnable(p))
		return;
		
#ifdef CONFIG_SMP
	handle_cpu_migration(p, cpu);
#endif
	RTS_SET(p, RTS_NO_QUANTUM);
}

static void update_process_priority(struct proc *p, int priority)
{
	if (priority != INVALID_PRIORITY)
		p->p_priority = priority;
}

static void update_process_quantum(struct proc *p, int quantum)
{
	if (quantum != INVALID_QUANTUM) {
		p->p_quantum_size_ms = quantum;
		p->p_cpu_time_left = ms_2_cpu_time(quantum);
	}
}

#ifdef CONFIG_SMP
static void update_process_cpu(struct proc *p, int cpu)
{
	if (cpu != INVALID_CPU)
		p->p_cpu = cpu;
}
#endif

static void update_process_nice(struct proc *p, int niced)
{
	if (niced)
		p->p_misc_flags |= MF_NICED;
	else
		p->p_misc_flags &= ~MF_NICED;
}

int sched_proc(struct proc *p, int priority, int quantum, int cpu, int niced)
{
	int result = validate_parameters(priority, quantum, cpu);
	if (result != OK)
		return result;
	
	prepare_runnable_process(p, cpu);
	
	update_process_priority(p, priority);
	update_process_quantum(p, quantum);
#ifdef CONFIG_SMP
	update_process_cpu(p, cpu);
#endif
	update_process_nice(p, niced);
	
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
	ipc_filter_t *ipcf;

	if (!is_valid_filter_type(type))
		return EINVAL;

	num_elements = validate_filter_length(length);
	if (num_elements < 0)
		return num_elements;

	ipcf = allocate_filter_slot(type);
	if (ipcf == NULL)
		return ENOMEM;

	r = initialize_filter(ipcf, rp, address, length, num_elements);
	if (r != OK) {
		IPCF_POOL_FREE_SLOT(ipcf);
		return r;
	}

	append_filter_to_chain(rp, ipcf);
	return OK;
}

static int is_valid_filter_type(int type)
{
	return (type == IPCF_BLACKLIST || type == IPCF_WHITELIST);
}

static int validate_filter_length(size_t length)
{
	int num_elements;

	if (length % sizeof(ipc_filter_el_t) != 0)
		return -EINVAL;

	num_elements = length / sizeof(ipc_filter_el_t);
	if (num_elements <= 0 || num_elements > IPCF_MAX_ELEMENTS)
		return -E2BIG;

	return num_elements;
}

static ipc_filter_t* allocate_filter_slot(int type)
{
	ipc_filter_t *ipcf;
	IPCF_POOL_ALLOCATE_SLOT(type, &ipcf);
	return ipcf;
}

static int initialize_filter(ipc_filter_t *ipcf, struct proc *rp,
	vir_bytes address, size_t length, int num_elements)
{
	int r;

	ipcf->num_elements = num_elements;
	ipcf->next = NULL;
	
	r = data_copy(rp->p_endpoint, address,
		KERNEL, (vir_bytes)ipcf->elements, length);
	if (r != OK)
		return r;

	return check_ipc_filter(ipcf, TRUE);
}

static void append_filter_to_chain(struct proc *rp, ipc_filter_t *ipcf)
{
	ipc_filter_t **ipcfp;

	ipcfp = &priv(rp)->s_ipcf;
	while (*ipcfp != NULL)
		ipcfp = &(*ipcfp)->next;
	
	*ipcfp = ipcf;
}

/*===========================================================================*
 *				clear_ipc_filters			     *
 *===========================================================================*/
void clear_ipc_filters(struct proc *rp)
{
	free_ipc_filter_chain(rp);
	priv(rp)->s_ipcf = NULL;
	notify_vm_if_needed(rp);
}

static void free_ipc_filter_chain(struct proc *rp)
{
	ipc_filter_t *curr_ipcf, *ipcf;

	ipcf = priv(rp)->s_ipcf;
	while (ipcf != NULL) {
		curr_ipcf = ipcf;
		ipcf = ipcf->next;
		IPCF_POOL_FREE_SLOT(curr_ipcf);
	}
}

static void notify_vm_if_needed(struct proc *rp)
{
	if (!is_vm_process(rp) || !has_pending_vm_requests())
		return;

	if (send_sig(VM_PROC_NR, SIGKMEM) != OK)
		panic("send_sig failed");
}

static int is_vm_process(struct proc *rp)
{
	return rp->p_endpoint == VM_PROC_NR;
}

static int has_pending_vm_requests(void)
{
	return vmrequest != NULL;
}

/*===========================================================================*
 *				check_ipc_filter			     *
 *===========================================================================*/
int check_ipc_filter(ipc_filter_t *ipcf, int fill_flags)
{
	if (ipcf == NULL)
		return OK;

	int flags = calculate_flags(ipcf);
	if (flags == EINVAL)
		return EINVAL;

	return validate_or_set_flags(ipcf, flags, fill_flags);
}

static int calculate_flags(ipc_filter_t *ipcf)
{
	int flags = 0;
	
	for (int i = 0; i < ipcf->num_elements; i++) {
		ipc_filter_el_t *ipcf_el = &ipcf->elements[i];
		if (!IPCF_EL_CHECK(ipcf_el))
			return EINVAL;
		flags |= ipcf_el->flags;
	}
	
	return flags;
}

static int validate_or_set_flags(ipc_filter_t *ipcf, int flags, int fill_flags)
{
	if (fill_flags)
		ipcf->flags = flags;
	else if (ipcf->flags != flags)
		return EINVAL;
	return OK;
}

/*===========================================================================*
 *				allow_ipc_filtered_msg			     *
 *===========================================================================*/
int should_copy_message_type(ipc_filter_t *ipcf)
{
#if DEBUG_DUMPIPCF
	return TRUE;
#else
	while (ipcf) {
		if (ipcf->flags & IPCF_MATCH_M_TYPE) {
			return TRUE;
		}
		ipcf = ipcf->next;
	}
	return FALSE;
#endif
}

int copy_message_type(endpoint_t src_e, vir_bytes m_src_v, message *m_buff)
{
	int r = data_copy(src_e,
		m_src_v + offsetof(message, m_type), KERNEL,
		(vir_bytes)&m_buff->m_type, sizeof(m_buff->m_type));
	
	if (r != OK) {
#if DEBUG_DUMPIPCF
		printf("KERNEL: allow_ipc_filtered_msg: data "
			"copy error %d, allowing message...\n", r);
#endif
		return TRUE;
	}
	return FALSE;
}

int check_filter_match(ipc_filter_t *ipcf, message *m_src_p)
{
	int i;
	ipc_filter_el_t *ipcf_el;
	
	for (i = 0; i < ipcf->num_elements; i++) {
		ipcf_el = &ipcf->elements[i];
		if (IPCF_EL_MATCH(ipcf_el, m_src_p)) {
			return TRUE;
		}
	}
	return FALSE;
}

int evaluate_filters(ipc_filter_t *ipcf, message *m_src_p)
{
	int allow = (ipcf->type == IPCF_BLACKLIST);
	
	while (ipcf) {
		if (allow != (ipcf->type == IPCF_WHITELIST)) {
			if (check_filter_match(ipcf, m_src_p)) {
				allow = (ipcf->type == IPCF_WHITELIST);
			}
		}
		ipcf = ipcf->next;
	}
	
	return allow;
}

int allow_ipc_filtered_msg(struct proc *rp, endpoint_t src_e,
	vir_bytes m_src_v, message *m_src_p)
{
	int allow;
	ipc_filter_t *ipcf;
	message m_buff;

	ipcf = priv(rp)->s_ipcf;
	if (ipcf == NULL)
		return TRUE;

	if (m_src_p == NULL) {
		assert(m_src_v != 0);

		if (should_copy_message_type(ipcf)) {
			if (copy_message_type(src_e, m_src_v, &m_buff)) {
				return TRUE;
			}
		}
		m_src_p = &m_buff;
	}

	m_src_p->m_source = src_e;
	allow = evaluate_filters(ipcf, m_src_p);

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
	struct proc *vmp;
	message m_buf;

	vmp = proc_addr(VM_PROC_NR);

	if (priv(vmp)->s_ipcf == NULL)
		return TRUE;

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
    struct priv *priv = priv(rp);
    
    priv->s_flags |= CHECK_IRQ;
    
    if (irq_already_exists(priv, irq)) {
        return OK;
    }
    
    return add_new_irq(priv, irq, rp->p_endpoint);
}

static int irq_already_exists(struct priv *priv, int irq)
{
    int i;
    for (i = 0; i < priv->s_nr_irq; i++) {
        if (priv->s_irq_tab[i] == irq) {
            return 1;
        }
    }
    return 0;
}

static int add_new_irq(struct priv *priv, int irq, int endpoint)
{
    if (priv->s_nr_irq >= NR_IRQ) {
        printf("do_privctl: %d already has %d irq's.\n",
            endpoint, priv->s_nr_irq);
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
    struct priv *priv = priv(rp);
    
    priv->s_flags |= CHECK_IO_PORT;
    
    if (io_range_exists(priv, ior)) {
        return OK;
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

static int io_range_exists(struct priv *priv, struct io_range *ior)
{
    int i;
    for (i = 0; i < priv->s_nr_io_range; i++) {
        if (priv->s_io_tab[i].ior_base == ior->ior_base &&
            priv->s_io_tab[i].ior_limit == ior->ior_limit) {
            return 1;
        }
    }
    return 0;
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

    i = priv->s_nr_mem_range;
    if (i >= NR_MEM_RANGE) {
        printf("do_privctl: %d already has %d mem ranges.\n",
            rp->p_endpoint, i);
        return ENOMEM;
    }
    priv->s_mem_tab[i] = *memr;
    priv->s_nr_mem_range++;
    return OK;
}

