// FIXME if syscall argv is invalid, simply return error without doing any syscall
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <cspace/cspace.h>
#include <serial/serial.h>
#include <clock/clock.h>
#include "comm/comm.h"
#include "vm/vmem_layout.h"
#include "handle_syscall.h"

#define verbose  -1
#include <sys/debug.h>
#include <sys/panic.h>
#include "dev/console.h"
#include "vm/frametable.h"
#include "vm/address_space.h"
#include "vm/vm.h"
#include "proc/proc.h"
#include "syscall.h"
#include "vm/pagetable.h"
#include <sos.h>
#include "fs/file_syscall.h"

// used to replace the long switch case in `handle_syscall`
#define NUMBER_OF_SYSCALL   100

// .will_block is not used actually
syscall_func syscall_func_arr[NUMBER_OF_SYSCALL] = {
    {.syscall=&sos_syscall_print_to_console, .will_block=false},
    {.syscall=&sos_syscall_read, .will_block=true},
    {.syscall=&sos_syscall_write, .will_block=false},
    {.syscall=&sos_syscall_open, .will_block=false},
    {.syscall=&sos_syscall_usleep, .will_block=true},
    {.syscall=&sos_syscall_time_stamp, .will_block=false},
    {.syscall=&sos_syscall_brk, .will_block=false},
    {.syscall=&sos_syscall_close, .will_block=false},
    {.syscall=&sos_syscall_stat, .will_block=false},
    {.syscall=&sos_syscall_get_dirent, .will_block=false},
    {.syscall=&sos_syscall_remove, .will_block=false},
    {.syscall=&sos_syscall_create_process, .will_block=false},
    {.syscall=&sos_syscall_delete_process, .will_block=false},
    {.syscall=&sos_syscall_wait_process, .will_block=false},
    {.syscall=&sos_syscall_process_status, .will_block=false},
    {.syscall=&sos_syscall_exit_process, .will_block=false}};

extern timestamp_t g_cur_timestamp_us;
/* extern struct serial * serial_handler = NULL; */
extern struct serial_console _serial;

/* for process creation */
extern seL4_CPtr _sos_ipc_ep_cap;
extern struct proc* proc_array[PROC_ARRAY_SIZE];

/*
*   In M4, assume read from/write to console device
*/

bool path_transfer(char* in, size_t off)
{
    //FIXME
    static char file_name [4096];
    if (off >= APP_PROCESS_IPC_SHARED_BUFFER_SIZE - 20)
    {
        return false;
    }
    /* assert(off <= APP_PROCESS_IPC_SHARED_BUFFER_SIZE); */
    memcpy(file_name, in, off);
    file_name[off] = 0;
    int out_len = 0;
    if (strcmp(file_name, "console") == 0)
    {
        file_name[off] = ':';
        out_len = off + 1;
    }
    else
    {
        memcpy(file_name, "nfs:", 4);
        memcpy(file_name + 4, in ,  off );
        out_len = off + 4;
    }
    file_name[out_len] = 0;
    out_len += 1;
    memcpy(in, file_name, out_len);
    return true;

}

void sos_syscall_read(void* argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());
    struct ipc_buffer_ctrl_msg* msg = &(proc->p_ipc_ctrl);
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "begin sos_syscall_read, from pid: %u\n", proc->p_pid);
    /* COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "* fd: %d, readlen: %d %d\n",msg->file_id, msg->offset, APP_PROCESS_IPC_SHARED_BUFFER_SIZE); */
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "* fd: %d, readlen: %d\n",msg->file_id, msg->offset);
    size_t read_len = 0;
    assert(msg->offset <=  APP_PROCESS_IPC_SHARED_BUFFER_SIZE);
    int ret = syscall_read(msg->file_id, (char*)get_ipc_buffer(proc), msg->offset, &read_len);
    struct ipc_buffer_ctrl_msg ctrl;
    if (ret == 0 )
    {
        ctrl.offset = read_len;
        ctrl.ret_val = 0;

        COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "end sos_syscall_read pid: %u, read len: %d\n", proc->p_pid,  ctrl.offset);
    }
    else
    {
        ctrl.offset = 0;
        ctrl.ret_val = read_len;

        ERROR_DEBUG("end sos_syscall_write pid: %u, err: %d\n", proc->p_pid, read_len);
    }
    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

// Remove files
void sos_syscall_remove(void * argv) {
    struct proc * proc = (struct proc *) argv;
    assert(proc == get_current_proc());
    struct ipc_buffer_ctrl_msg* msg = &(proc->p_ipc_ctrl);

    char* file_name = (get_ipc_buffer(proc));
    path_transfer(file_name, msg->offset);
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "sos_syscall_remove: [%s]\n", file_name);

    int err = 0;
    int ret = syscall_remove(file_name, &err);

    conditional_panic(ret, "Fail to remove files from nfs\n");
    // assert(ret == 0);
    struct ipc_buffer_ctrl_msg reply_cmsg;
    reply_cmsg.offset = 0;
    reply_cmsg.ret_val = ret;
    ipc_reply(&reply_cmsg, &(proc->p_reply_cap));
}

void sos_syscall_open(void* argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());


    char* file_name = (get_ipc_buffer(proc));
    struct ipc_buffer_ctrl_msg ctrl;
    if (path_transfer(file_name, proc->p_ipc_ctrl.offset) == false)
    {
        ctrl.ret_val = EINVAL;
        ERROR_DEBUG("end sos_syscall_open proc: %u, file: [%s] err: %d\n",proc->p_pid, file_name, ctrl.ret_val);
        ipc_reply(&ctrl, &(proc->p_reply_cap));
        return;
    }
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "begin sos_syscall_open proc: %u, file: [%s] flags: %d, mode: %d\n",proc->p_pid, file_name, proc->p_ipc_ctrl.mode, proc->p_ipc_ctrl.mode);

    int fd = 0;
    int ret = syscall_open(file_name, proc->p_ipc_ctrl.mode, proc->p_ipc_ctrl.mode, &fd);
    ctrl.offset = 0;
    if (ret == 0 )
    {
        ctrl.ret_val = 0;
        ctrl.file_id = fd;
        COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "end sos_syscall_open proc: %u, file: [%s] fd: %d\n",proc->p_pid, file_name, fd);

    }
    else
    {
        ERROR_DEBUG("end sos_syscall_open proc: %u, file: [%s] err: %d\n",proc->p_pid, file_name, fd);
        ctrl.ret_val = fd;
    }
    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

void sos_syscall_close(void* argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());

    int err = 0;
    syscall_close(proc->p_ipc_ctrl.file_id, &err);
    struct ipc_buffer_ctrl_msg ctrl;
    ctrl.ret_val = err;
    ctrl.offset = 0;
    if (ctrl.ret_val)
    {
        ERROR_DEBUG("sos_syscall_close proc: %u, fd: %d, err: %d\n", proc->p_pid, proc->p_ipc_ctrl.file_id, err);
    }
    else
    {
        COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "sos_syscall_close proc: %u, fd: %d success!\n", proc->p_pid, proc->p_ipc_ctrl.file_id);
    }
    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

void sos_syscall_time_stamp(void * argv)
{
    dump_vm_state();
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());
    timestamp_t now = g_cur_timestamp_us;
    memcpy(get_ipc_buffer(proc), &now, 8);
    struct ipc_buffer_ctrl_msg ctrl;
    ctrl.ret_val = 0;
    ctrl.offset = 0;
    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

// This function correspond to `sos_write` defined in APP scope in `sos.h`
void sos_syscall_print_to_console(void * argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());

	// seL4_Word start_app_addr = seL4_GetMR(1);

    seL4_Word start_sos_addr = (seL4_Word)get_ipc_buffer(proc);

    // int offset = seL4_GetMR(2);
    int offset = proc->p_ipc_ctrl.offset;

    // bypass fs/vfs check, because it may not open "console:""
    int ret = serial_send(_serial._serial_handler, (char *)start_sos_addr, offset);
    /* if (offset < APP_PROCESS_IPC_SHARED_BUFFER_SIZE) */
    /*     ((char*)(start_sos_addr))[offset] = 0; */
    /* else */
    /*     ((char*)(start_sos_addr))[offset - 1]  = 0; */

    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_YELLOW,
        "[sos] serial send len: %d\n",ret);
    assert(ret > 0);
    struct ipc_buffer_ctrl_msg ctrl;
    ctrl.ret_val = 0;
    ctrl.offset = ret;
    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

void sos_syscall_write(void* argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "begin sos_syscall_write pid: %u\n", proc->p_pid);
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "* fd: %d, writelen: %d\n", proc->p_ipc_ctrl.file_id, proc->p_ipc_ctrl.offset);

    size_t write_len = 0;
    struct ipc_buffer_ctrl_msg* msg = &(proc->p_ipc_ctrl);
    assert(msg->offset <=  APP_PROCESS_IPC_SHARED_BUFFER_SIZE);
    int ret = syscall_write(msg->file_id, (char*)get_ipc_buffer(proc), msg->offset, &write_len);
    struct ipc_buffer_ctrl_msg ctrl;
    if (ret == 0 )
    {
        ctrl.ret_val = 0;
        ctrl.offset = write_len;
        COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "end sos_syscall_write pid: %u, write len: %d\n", proc->p_pid,  ctrl.offset);
    }
    else
    {
        ERROR_DEBUG("end sos_syscall_write pid: %u, err: %d\n", proc->p_pid, write_len);
        ctrl.ret_val = write_len;
        ctrl.offset = 0;
    }
    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

void sos_syscall_usleep(void * argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());
    int msecond = *((int*)(get_ipc_buffer(proc)));
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "proc %u, get sleep %dms\n", proc->p_pid, msecond);
    handle_block_sleep((void*)(msecond));
}

void sos_syscall_stat(void* argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());
    // FIXME
    char* file_name = (get_ipc_buffer(proc));
    struct ipc_buffer_ctrl_msg ctrl;
    if (path_transfer(file_name, proc->p_ipc_ctrl.offset) == false)
    {
        ctrl.ret_val = EINVAL;
        ERROR_DEBUG("end sos_syscall_stat proc: %u, file: [%s] err: %d\n",proc->p_pid, file_name, ctrl.ret_val);
        ipc_reply(&ctrl, &(proc->p_reply_cap));
        return;
    }
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "begin sos_syscall_stat proc: %u, file: [%s]\n", proc->p_pid, file_name);

    struct stat buf;
    int ret = syscall_stat(file_name, &buf);
    ctrl.ret_val = ret;
    ctrl.offset = 0;
    if (ctrl.ret_val == 0)
    {
        ctrl.offset = sizeof (sos_stat_t);
        sos_stat_t* sos_stat = ( sos_stat_t* )( get_ipc_buffer(proc));
        sos_stat->st_type =  buf.st_type;
        sos_stat->st_fmode = buf.st_mode;
        sos_stat->st_size = buf.st_size;
        sos_stat->st_ctime = (long)(buf.st_ctime);
        sos_stat->st_atime = (long)(buf.st_atime) ;
        /* sos_stat->st_mtime = (long)(buf.st_mtime) ; */
        COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN,"end sos_syscall_stat proc: %u, file: \n", proc->p_pid, file_name);
        COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN,"* type: %d, mode: %d, size: %d, ctime: %ld, atime: %ld\n", sos_stat->st_type, sos_stat->st_fmode, (int)(sos_stat->st_size), sos_stat->st_ctime, sos_stat->st_atime);
    }
    else
    {
        ERROR_DEBUG("end sos_syscall_stat proc: %u, err: %d\n", proc->p_pid, ctrl.ret_val);
    }
    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

void sos_syscall_get_dirent(void* argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());
    struct ipc_buffer_ctrl_msg* in = &(proc->p_ipc_ctrl);

    assert(in->offset == 2 * sizeof(int));
    int pos = *(int*)(get_ipc_buffer(proc));
    int file_name_len = *(int*)((size_t)(get_ipc_buffer(proc)) + 4);
    char* name = (char*)(get_ipc_buffer(proc));
    file_name_len = file_name_len > APP_PROCESS_IPC_SHARED_BUFFER_SIZE - 1 ? APP_PROCESS_IPC_SHARED_BUFFER_SIZE - 1: file_name_len;
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "begin sos_syscall_get_dirent, proc: %u, pos: %d, given length %d for storing file name\n", proc->p_pid, pos, file_name_len);

    // currently only support nfs.
    char path[10] ;
    memcpy(path, "nfs:", 4);
    memset(name, 0, APP_PROCESS_IPC_SHARED_BUFFER_SIZE);
    int ret = syscall_get_dirent(path, pos, name, file_name_len);
    struct ipc_buffer_ctrl_msg ctrl;
    if (ret != 0)
    {
        COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_RED, "end sos_syscall_get_dirent, proc: %u, pos: %d, err: %d\n", proc->p_pid, pos, ret);
        ctrl.ret_val = ret;
        ctrl.offset = 0;
    }
    else
    {
        COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "end sos_syscall_get_dirent, proc: %u, file[%s]\n", proc->p_pid, name);
        ctrl.ret_val = 0;
        ctrl.offset = strlen(name);
        assert(ctrl.offset <= APP_PROCESS_IPC_SHARED_BUFFER_SIZE);
    }
    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

void sos_syscall_brk(void* argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());
    seL4_Word newbrk = *((int*)(get_ipc_buffer(proc)));

    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "begin sos_syscall_brk proc %u, newbrk: 0x%x\n", proc->p_pid, newbrk);

    struct addrspace *as = proc->p_addrspace;
    seL4_Word retbrk = 0;

    struct ipc_buffer_ctrl_msg ctrl;
    int ret = as_get_heap_brk(as, newbrk, &retbrk);
    ctrl.ret_val = ret;
    ctrl.offset = 4;
    if (ret == 0)
    {
        memcpy(get_ipc_buffer(proc), &retbrk, 4);
    }
    COLOR_DEBUG(DB_SYSCALL, ret == 0 ? ANSI_COLOR_GREEN : ANSI_COLOR_RED, "end sos_syscall_brk proc %u, return brk: 0x%x, ret: %d\n", proc->p_pid,retbrk, ret);

    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

void sos_syscall_create_process(void * argv)
{
    struct proc* proc = (struct proc*) argv;
    // assert(proc == get_current_proc());

    char* ipc_buf = (get_ipc_buffer(proc));
    struct ipc_buffer_ctrl_msg ctrl;
    ctrl.offset = 0;

    char proc_name[proc->p_ipc_ctrl.offset + 1];
    memcpy(proc_name, ipc_buf, proc->p_ipc_ctrl.offset);
    proc_name[proc->p_ipc_ctrl.offset] = '\0';

    struct proc * new_proc = proc_create(proc_name, _sos_ipc_ep_cap);
    if (new_proc == NULL)
    {
        ctrl.ret_val = ENOMEM;
        ctrl.file_id = -1;
        ipc_reply(&ctrl, &(proc->p_reply_cap));
        return;
    }



    proc_activate(new_proc);

    ctrl.ret_val = 0;
    ctrl.file_id = new_proc->p_pid;
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "end sos_syscall_create_process proc: %u\n",proc->p_pid);

    ipc_reply(&ctrl, &(proc->p_reply_cap));
}


void sos_syscall_wait_process(void * argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(proc == get_current_proc());

    struct ipc_buffer_ctrl_msg ctrl;
    ctrl.offset = 0;
    pid_t pid = proc->p_ipc_ctrl.file_id;
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, " proc: %u wait for %u\n",proc->p_pid, pid);
    struct proc* wait_proc = proc_get_child(pid);
    if (wait_proc == NULL)
    {
        ERROR_DEBUG("not find the child proc\n");
        ctrl.ret_val = ECHILD;
        goto wait_end;
    }
    assert(!list_empty(&proc->as_child_next)); // FIXME has this child.
    if (wait_proc->p_status == PROC_STATUS_ZOMBIE)
    {
        ERROR_DEBUG("zombie proc exit\n");
        ctrl.ret_val = 0;
        proc_destroy(wait_proc);
        goto wait_end;
    }
    else
    {
        proc->p_waitchild = sem_create("waiting child", 0, -1);
        if (proc->p_waitchild == NULL)
        {
            ERROR_DEBUG("no enough mem creating sem\n");
            ctrl.ret_val = ENOMEM;
            goto wait_end;
        }
        wait_proc->someone_wait = true;
        COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, " proc: %u now  blocks waiting for %u\n",proc->p_pid, pid);

        P(proc->p_waitchild);
        wait_proc->someone_wait = false;
        sem_destroy(proc->p_waitchild);
        proc_deattch(wait_proc);
        proc_destroy(wait_proc);
    }
wait_end:
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, " proc: %u wait for %u finish: %d\n",proc->p_pid, pid, ctrl.ret_val);
    ipc_reply(&ctrl, &(proc->p_reply_cap));
    return;
}

void sos_syscall_delete_process(void * argv)
{
    struct proc* proc = (struct proc*) argv;

    struct ipc_buffer_ctrl_msg ctrl;
    ctrl.offset = 0;
    ctrl.ret_val = 0;
    ctrl.file_id = 0;
    int pid = proc->p_ipc_ctrl.file_id;
    struct proc * proc_to_be_deleted = get_proc_by_pid(pid);
    if (!proc_to_be_deleted || pid == 0) // you can not kill kproc!
    {
        ctrl.ret_val = ESRCH;
        ipc_reply(&ctrl, &(proc->p_reply_cap));
        return;
    }

    // like linux D status, you can't kill it while blocked on nfs or something else
    if (coro_status(proc_to_be_deleted->p_coro) == COROUTINE_SUSPEND)
    {
        ctrl.ret_val = EPERM;
        ipc_reply(&ctrl, &(proc->p_reply_cap));
        return;
    }
    proc_exit(proc_to_be_deleted);
    bool wakeup = proc_wakeup_father(proc_to_be_deleted);
    if (!wakeup)
    {
        proc_attach_kproc(proc);
    }

    /* if (proc != get_current_proc()) */
    /*     coro_stop(proc->p_coro);  //make sure app coro not schedule again */

    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "end sos_syscall_delete_process proc\n");

    // TODO we need write something on nc
    if (proc_to_be_deleted != get_current_proc())
        ipc_reply(&ctrl, &(proc->p_reply_cap));
}


void sos_syscall_process_status(void * argv)
{
    struct proc* proc = (struct proc*) argv;
    void* ipc_buf = (get_ipc_buffer(proc));
    int ps_amount = *(int *)ipc_buf;

    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "begin sos_syscall_process_status proc %u\n", proc->p_pid);

    // Temporary array to hold return values
    sos_process_t * processes = (sos_process_t *)malloc(ps_amount * sizeof(sos_process_t));
    // loop through proc_array and try to find proper process pointer
    int i = 0; // If don't want to display the SOS and SOSH, start from 2
    int j = 0;
    while (i < PROC_ARRAY_SIZE && j < ps_amount)
    {
        if (proc_array[i] == NULL || proc_array[i]->p_status == PROC_STATUS_ZOMBIE)
        {
            i++;
            continue;
        }

        processes[j].pid = proc_array[i]->p_pid;
        processes[j].size = 12345; // ??? maybe something like get_proc_size(proc_array[i]);
        processes[j].stime = proc_array[i]->stime;
        strcpy(processes[j].command, proc_array[i]->p_name);

        printf("~~~~~~~~~~~~~~processes[j].command: %s\n", processes[j].command);

        i++;
        j++;
    }

    // write processes array and ps_amount to share buffer, then reply
    memcpy((int *)ipc_buf, &j, sizeof(int));
    memcpy((sos_process_t *)(ipc_buf + sizeof(int)), processes, j * sizeof(sos_process_t));

    struct ipc_buffer_ctrl_msg ctrl;
    ctrl.ret_val = 0;
    ctrl.offset = sizeof(int) + j * sizeof(sos_process_t);

    ipc_reply(&ctrl, &(proc->p_reply_cap));
}

// try to kill itself
void sos_syscall_exit_process(void* argv)
{
    struct proc* proc = (struct proc*) argv;
    assert(get_current_proc() == proc);
    proc_exit(proc);
    bool wakeup = proc_wakeup_father(proc);
    // let kproc to recycle this proc, which is not same semetic as linux
    if (!wakeup)
    {
        proc_attach_kproc(proc);
    }
}

void handle_syscall(seL4_Word badge, struct proc * app_process)
{
    seL4_Word syscall_number;
    seL4_CPtr reply_cap;

    struct ipc_buffer_ctrl_msg * ctrl_msg = &(app_process->p_ipc_ctrl);
    memcpy(ctrl_msg, seL4_GetIPCBuffer()->msg, sizeof(ipc_buffer_ctrl_msg));

    syscall_number = ctrl_msg->syscall_number;
    COLOR_DEBUG(DB_SYSCALL, ANSI_COLOR_GREEN, "proc: %u, syscall_number: %d, msg_len: %d\n",
        app_process->p_pid, syscall_number, ctrl_msg->offset);

    assert(coro_status(app_process->p_coro) == COROUTINE_INIT);
    /* Save the caller */
    assert(app_process->p_reply_cap == 0);
    if (syscall_number != SOS_SYSCALL_PROCESS_EXIT)
    {
        reply_cap = cspace_save_reply_cap(cur_cspace);
        assert(reply_cap != CSPACE_NULL);

        // in case the app process block, the reply_cap and message get flushed
        // we put these into `proc struct`
        app_process->p_reply_cap = reply_cap;
    }

    if (syscall_number < 0 || syscall_number > NUMBER_OF_SYSCALL) {
        printf("%s:%d (%s) Unknown syscall %d\n",
                       __FILE__, __LINE__, __func__, syscall_number);
        assert("unknown syscall number!\n");
    }

    /* Invoke corresponding syscall */
    restart_coro(app_process->p_coro, syscall_func_arr[syscall_number].syscall, app_process);
}



