/*
    Process related operations
*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <sel4/types.h>
#include <cspace/cspace.h>
#include <mapping.h>
#include <ut_manager/ut.h>
#include <vm/vmem_layout.h>
#include <elf/elf.h>
#include <cpio/cpio.h>
#include "comm/comm.h"

#define verbose 5
#include <sys/debug.h>
#include <sys/panic.h>

#include "proc.h"
#include "vm/address_space.h"
#include "vm/pagetable.h"
#include "vm/vm.h"
#include "clock/clock.h"

#include "syscall/handle_syscall.h"

struct proc kproc;

// TODO, now we assume there is only one process, and the badge
// is hard coded, may try create badge dynamically
/* #define TEMP_ONE_PROCESS_BADGE (1<<3) */

extern char _cpio_archive[];

static void clear_proc(struct proc* proc)
{
    proc->p_name = NULL;
    proc->p_pid = 0;
    proc->p_addrspace = NULL;
    proc->p_pagetable = NULL;
    proc->p_tcb = NULL;
    proc->p_croot = NULL;
    proc->p_ep_cap = 0;
    proc->p_coro = NULL;
    proc->p_reply_cap = 0;
    proc->fs_struct = NULL;
    proc->p_status = PROC_STATUS_RUNNING;
}

/*
*   Use proc_id % PROC_ARRAY_SIZE to retrieve the location on proc_array
*   Design, the proc_id may greater than the size of proc_array, so that
*   the reuse of proc_id will have to experience a longer time, which will
*   help to mitigate the problem may happen with proc id reuse
*/

struct proc* proc_array[PROC_ARRAY_SIZE] = {NULL}; // make sure it initialized as NULL
int proc_id_counter = 0;

static void init_kproc(char* kname)
{
    clear_proc(&kproc);
    kproc.p_name = kname;
    kproc.p_pid = proc_id_counter;
    kproc.p_pagetable = (struct pagetable*)(kcreate_pagetable());
    kproc.p_addrspace = NULL; // i don't need the restriction.
    kproc.p_tcb = NULL;
    kproc.p_croot = NULL;
    kproc.p_ep_cap = 0;
    kproc.stime = 0;
    set_kproc_coro(&kproc);
    /* should be proc-id 0, the very first proc*/
    proc_array[proc_id_counter++] = &kproc;
}

void proc_bootstrap()
{
    static char* kname = "sos_kernel";
    bootstrap_coro_env();
    init_kproc(kname);
    COLOR_DEBUG(DB_THREADS, ANSI_COLOR_GREEN, "kernel proc at: %p, coroutine at: %p\n", &kproc, kproc.p_coro)
}

struct proc * get_proc_by_pid(int pid)
{
    struct proc * temp = proc_array[pid % PROC_ARRAY_SIZE];
    assert(temp != NULL);
    return temp;
}

/* void loop_through_region(struct addrspace *as); */

static int find_next_proc_id() 
{
    if (proc_id_counter >= MAX_PROC_ID) {
        proc_id_counter = 0;
    }   

    int i = PROC_ARRAY_SIZE;
    while(proc_array[proc_id_counter % PROC_ARRAY_SIZE] != NULL) {
        if (proc_array[proc_id_counter % PROC_ARRAY_SIZE]->p_status != PROC_STATUS_RUNNING) 
        {
            break;
        }

        proc_id_counter++;
        if (proc_id_counter >= MAX_PROC_ID) {
            proc_id_counter = 0;
        }
        if (--i <= 0) {
            break;
        }
    }

    // if can't find an empty slot on proc_array
    if (i <= 0) {
        return -1;
    }

    if (proc_array[proc_id_counter % PROC_ARRAY_SIZE] == NULL) {
        return proc_id_counter++;
    } else if (proc_array[proc_id_counter % PROC_ARRAY_SIZE]->p_status == PROC_STATUS_ZOMBIE) {
        // no longer in use, then, help to clean that up.
        proc_destroy(proc_array[proc_id_counter % PROC_ARRAY_SIZE]);
        proc_array[proc_id_counter % PROC_ARRAY_SIZE] = NULL;
        return proc_id_counter++; 
    } else {
        // should not reach here
        assert(0);
        return -1;
    }
}


struct proc* proc_create(char* name, seL4_CPtr fault_ep_cap)
{
    int err;
    struct proc * process = (struct proc *)malloc(sizeof(struct proc));
    if (process == NULL)
    {
        return NULL;
    }
    clear_proc(process);

    int proc_id = find_next_proc_id();

    if (proc_id == -1) {
        free(process);
        return NULL;
    }

    // should not assign name to p_name, because name will be deleted 
    // in the near future. Thne p_name point to random stuff.
    process->p_name = strdup(name);
    process->p_pid = proc_id;
    process->p_badge = proc_id % PROC_ARRAY_SIZE;
    proc_array[proc_id % PROC_ARRAY_SIZE] = process;
    process->stime = time_stamp();

    /*
    *  pagetable will take care of the virtual address root
    *  IPC buffer will be created and defined in address space
    *  Stack will be created and defined in address space
    */

    // Init address space and page table
    process->p_addrspace = as_create();
    if (process->p_addrspace == NULL)
    {
        ERROR_DEBUG("proc_create: get a null p_addrspace\n");
        proc_destroy(process);
        return NULL;
    }
    process->p_pagetable = create_pagetable();
    if (process->p_addrspace == NULL)
    {
        ERROR_DEBUG( "proc_create: get a null p_pagetable\n");
        proc_destroy(process);
        return NULL;
    }

    if( init_fd_table(process))
    {
        ERROR_DEBUG( "init_fd_table error\n");
        proc_destroy(process);
        return NULL;
    }
    process->p_addrspace->proc = process;

    // Create a simple 1 level CSpace
    process->p_croot = cspace_create(1);
    assert(process->p_croot != NULL);

    // the order is first init ipc buffer, then setup fault ep?
    as_define_ipc(process, process->p_addrspace);
    as_define_ipc_shared_buffer(process, process->p_addrspace);
    // Copy the fault endpoint to the user app to enable IPC
    process->p_ep_cap = cspace_mint_cap(process->p_croot,
                                        cur_cspace,
                                        fault_ep_cap,
                                        seL4_AllRights,
                                        seL4_CapData_Badge_new(process->p_badge));
    assert(process->p_ep_cap != CSPACE_NULL);
    assert(process->p_ep_cap == 1);// FIXME

    // Create a new TCB object
    struct sos_object * tcb_obj = (struct sos_object *)malloc(sizeof(struct sos_object));
    clear_sos_object(tcb_obj);
    err = init_sos_object(tcb_obj, seL4_TCBObject, seL4_TCBBits);
    conditional_panic(err, "Failed to create TCB");
    process->p_tcb = tcb_obj;

    // configure TCB
    // hardcode priority as 0
    err = seL4_TCB_Configure(process->p_tcb->cap,
                             process->p_ep_cap,
                             0,
                              process->p_croot->root_cnode,
                              seL4_NilData,
                              process->p_pagetable->vroot.cap,
                              seL4_NilData,
                              APP_PROCESS_IPC_BUFFER,
                              as_get_ipc_cap(process->p_addrspace));
    conditional_panic(err, "Unable to configure new TCB");

    // parse the cpio image
    unsigned long elf_size;
    // According to `extern char _cpio_archive[];` in main.c
    // It has been declared in main.c
    char * elf_base = cpio_get_file(_cpio_archive, name, &elf_size);
    conditional_panic(!elf_base, "Unable to locate cpio header");
    COLOR_DEBUG(DB_THREADS, ANSI_COLOR_GREEN, " elf_base: 0x%x, entry point: 0x%x   %s\n", (unsigned int)elf_base, (unsigned int)elf_getEntryPoint(elf_base), name);
    COLOR_DEBUG(DB_THREADS, ANSI_COLOR_GREEN, "name: %s\n", name);
    
    /*** load the elf image info, set up addrspace ***/
    // DATA and CODE region is set up by `vm_elf_load`
    err = vm_elf_load(process->p_addrspace, process->p_pagetable->vroot.cap, elf_base);
    conditional_panic(err, "Failed to load elf image");

    // This pointer here is useless act as a placeholder
    vaddr_t stack_pointer;
    as_define_stack(process->p_addrspace, &stack_pointer);

    as_define_heap(process->p_addrspace);

    // TODO: as_define_mmap(process->p_addrspace);

    loop_through_region(process->p_addrspace);

    // each user level process has one coroutine at sos side
    process->p_coro = create_coro(NULL, NULL);
    assert(process->p_coro != NULL);
    process->p_coro->_proc = process;

    process->p_reply_cap = 0;
    return process;
}

void proc_activate(struct proc * process)
{
    seL4_UserContext context;
    memset(&context, 0, sizeof(context));
    context.pc = elf_getEntryPoint(process->p_addrspace->elf_base);
    context.sp = APP_PROCESS_STACK_TOP;
    seL4_TCB_WriteRegisters(process->p_tcb->cap, 1, 0, 2, &context);
}

int proc_destroy(struct proc * process)
{
    assert(process->p_status == PROC_STATUS_ZOMBIE);
    // TODO free fs, free pid in M7
    destroy_reply_cap(&process->p_reply_cap);
    /* destroy_fd_table(process); TODO */

    if (process->p_addrspace != NULL)
    {
        as_destroy(process->p_addrspace);
        process->p_addrspace = NULL;
    }

    if (process->p_pagetable != NULL)
    {
        destroy_pagetable(process->p_pagetable);
        process->p_pagetable = NULL;
    }

    if (process->p_tcb != NULL)
    {
        seL4_TCB_Suspend(process->p_tcb->cap);
        free_sos_object(process->p_tcb, seL4_TCBBits);
        process->p_tcb = NULL;
    }

    /* // revoke & delete capability */
    assert(0 == cspace_revoke_cap(process->p_croot, process->p_ep_cap));
    assert(0 == cspace_delete_cap(process->p_croot, process->p_ep_cap));

    // mentioned in where it is defined, One could also rely on cspace_destroy() to free object,
    // if, and only if, there are no copies of caps to the object outside of the cspace being destroyed.
    // This should be a temporary solution
    cspace_destroy(process->p_croot);

    process->p_croot = NULL;

    destroy_coro(process->p_coro);
    free(process);
    COLOR_DEBUG(DB_THREADS, ANSI_COLOR_GREEN, "destroy process 0x%x ok!\n", process);
    return 0;
}

extern struct proc * test_process;
// FIXME in M7
void recycle_process()
{
    if (test_process != NULL && test_process->p_status == PROC_STATUS_ZOMBIE)
    {
        assert(get_current_proc() != test_process);
        proc_destroy(test_process);
        test_process = NULL;
        dump_vm_state();
    }
}
