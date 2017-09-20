/* Define the syscall processing functions in this file*/

#ifndef SOS_SYSCALL_H
#define SOS_SYSCALL_H

#include <sos.h>
#include "proc/proc.h"
#include <stdbool.h>

typedef struct syscall_func {
	void (*syscall)(void* );
	bool will_block;
} syscall_func;


// move the `handle_syscall` from main to this file
void handle_syscall(seL4_Word badge, struct proc * app_process);

// you can get control message via IPC within the function
void sos_syscall_print_to_console(void* proc);
void sos_syscall_open(void* proc);
void sos_syscall_read(void* proc);
void sos_syscall_write(void* proc);
void sos_syscall_usleep(void* proc);
void sos_syscall_time_stamp(void* proc);
void sos_syscall_brk(void * proc);
void sos_syscall_close(void * proc);
void sos_syscall_stat(void* argv);
void sos_syscall_get_dirent(void* argv);
void sos_syscall_remove(void* proc);
void sos_syscall_create_process(void* proc);
void sos_syscall_delete_process(void* proc);
void sos_syscall_wait_process(void* proc);
void sos_syscall_process_status(void* proc);
void sos_syscall_exit_process(void* proc);
void sos_syscall_process_my_pid(void* proc);


#endif // SOS_SYSCALL_H
