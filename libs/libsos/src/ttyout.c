/*
 * Copyright 2014, NICTA
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(NICTA_BSD)
 */

/****************************************************************************
 *
 *      $Id:  $
 *
 *      Description: Simple milestone 0 code.
 *      		     Libc will need sos_write & sos_read implemented.
 *
 *      Author:      Ben Leslie
 *
 ****************************************************************************/

#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ttyout.h"

#include <sel4/sel4.h>
#include "sys.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_WHITE    "\x1b[37m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void ttyout_init(void) {
    /* Perform any initialisation you require here */
}

static size_t sos_debug_print(const void *vData, size_t count) {
    size_t i;
    const char *realdata = vData;
    for (i = 0; i < count; i++)
        seL4_DebugPutChar(realdata[i]);
    return count;
}

/* size_t sos_write(void *vData, size_t count) { */
/*     //implement this to use your syscall */
/*     return sos_debug_print(vData, count); */
/* } */

/* size_t sos_read(void *vData, size_t count) { */
/*     //implement this to use your syscall */
/*     return 0; */
/* } */

int tty_debug_print(const char *fmt, ...)
{
    static char print_buf[4096];
	int ret;
    sos_debug_print(ANSI_COLOR_BLUE, sizeof(ANSI_COLOR_BLUE));
	va_list ap;
	va_start(ap, fmt);
    ret = vsnprintf(print_buf, sizeof(print_buf) - 1, fmt, ap);
	va_end(ap);
    ret = sos_debug_print(print_buf, ret);
    sos_debug_print(ANSI_COLOR_RESET, sizeof(ANSI_COLOR_RESET));
	return ret;
}


/// @brief: protocol type(4bytes) + msg length in bytes (4bytes) + msg([msg length] bytes)
///
/// @param:  buf
/// @param:  buflen
///
/// @return: actually ipc sent msg in bytes if success, otherwise negative number return
/* int req_ipc_print_console(char* buf, size_t buflen) */
/* { */
/*     // seL4_Word msg[seL4_MsgMaxLength]; therefore should multiply by 4 , transfer int to char */
/*     int max_char = seL4_MsgMaxLength * 4 - 8; // maximum bytes sent supported by ipc */
/*     int can_send_buflen = max_char > buflen ? buflen : max_char; */
/*  */
/*     seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 2 + (can_send_buflen) / 4 + (can_send_buflen % 4 == 0 ? 0 : 1)); */
/*     seL4_SetTag(tag); */
/*     seL4_SetMR(0, SYSCALL_IPC_PRINT_COLSOLE); */
/*     seL4_SetMR(1, can_send_buflen); */
/*     char* msg_buf  = (char*)(seL4_GetIPCBuffer()->msg + 2); */
/*  */
/*     memcpy(msg_buf, buf, can_send_buflen); */
/*  */
/*     seL4_MessageInfo_t rep_msginfo = seL4_Call(SYSCALL_ENDPOINT_SLOT, tag); */
/*     tty_debug_print("[tty] do sending buflen: %d\n", can_send_buflen); */
/*     assert(0 == seL4_MessageInfo_get_label(rep_msginfo)); */
/*     return seL4_GetMR(0); */
/*  */
/* } */
/*  */
/* static int total_send_len = 0; */
// size_t sos_write(void *vData, size_t count)
// { return 0;}
/* { */
/*     size_t sent_len = 0; */
/*     char *buf = (char * ) vData; */
/*     tty_debug_print("[tty] begin sos_write len: %d\n", count); */
/*     while (sent_len != count) */
/*     { */
/*         int ret =  req_ipc_print_console(buf + sent_len, count - sent_len); */
/*         if (ret < 0 || ret >= 10000000) */
/*         { */
/*             tty_debug_print("[tty] some error happen, give up retry. ret: %d, total sendlen: %d, total count: %d\n", ret, sent_len, count); */
/*             break; */
/*  */
/*         } */
/*         sent_len += ret; */
/*         tty_debug_print("[tty] already send %d\n", sent_len); */
/*     } */
/*     total_send_len += sent_len; */
/*     tty_debug_print("[tty] sos_write finish, tty totally sent till now: %d\n", total_send_len); */
/*     return sent_len; */
/* } */
/*  */
