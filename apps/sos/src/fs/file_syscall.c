/**
 * @file:   file.c
 * @brief:  implementation of io syscalls, open, write, close, lseek, dup2
 * @author: bladechen(chenshenglong1990@gmail.com)
 *
 * 2016-12-10
 */
#include "comm/comm.h"
#include "fdtable.h"
#include "file_syscall.h"
#include "proc/proc.h"
#include "coroutine/coro.h"

#define MAX_FILENAME_LENGTH 128

int syscall_open(const char* filename, int flags, mode_t mode, int* fd_num)
{
    int result = do_sys_open(-1, filename, flags, mode, get_current_proc()->fs_struct);
    if (result < 0)
    {
        *fd_num = result;
        return -1;
    }
    *fd_num = result;
    return 0;
}

int syscall_close(int fd_num, int* retval)
{
    *retval = do_sys_close(fd_num);
    return (*retval == 0 )? 0 : -1;
}
int syscall_read(int fd, char* buf, size_t buflen, size_t* retval)
{

    int result = do_sys_read(fd, buf, buflen);
    if (result < 0)
    {
        ERROR_DEBUG ("do sys read errorn\n");
        *retval = -result;
        return -1;
    }
    *retval = result;
    return 0;
}

int syscall_write(int fd,  const char* buf, size_t nbytes, size_t* retval)
{
    if (nbytes == 0)
    {
        int result = do_sys_write(fd, NULL, 0);
        *retval = result;
        return (*retval == 0)? 0: -1;

    }
    int result = do_sys_write(fd, buf, nbytes);
    if (result < 0)
    {
        *retval = - result;
        return -1;
    }
    *retval = result;
    return 0;
}
/* int syscall_lseek(int fd, off_t pos, int whence, off_t* retval) */
/* { */
/*     *retval = 0; */
/*     off_t r = do_sys_lseek(fd, pos, whence); */
/*     if (r < 0) */
/*     { */
/*         *retval = -r; */
/*         return -1; */
/*     } */
/*     KASSERT(r >= 0); */
/*     *retval = r; */
/*     return 0; */
/*  */
/* } */
/* int syscall_dup2(int oldfd, int newfd, int* retval) */
/* { */
/*     *retval  = do_sys_dup2(oldfd, newfd); */
/*     return (*retval == 0)? 0: -1; */
/*  */
/* } */
/* int syscall_write(int fd_num, const_userptr_t* buf, size_t length) */
/* { */
/*     int written_length = 0; */
/*     return written_length; */
/* } */