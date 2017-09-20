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
 *      Description: Simple milestone 0 test.
 *
 *      Author:			Godfrey van der Linden
 *      Original Author:	Ben Leslie
 *
 ****************************************************************************/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sel4/sel4.h>


#include "ttyout.h"

// Block a thread forever
// we do this by making an unimplemented system call.
static void
thread_block(void){
    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetTag(tag);
    seL4_SetMR(0, 1);

    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);
}

#include <utils/page.h>

#define NPAGES 27
#define TEST_ADDRESS 0x20000000

/* called from pt_test */

int tty_debug_print(const char *fmt, ...);
static char buff[27 * 4096 * 2];
static void
do_pt_test(char *buf)
{

    /* set */
    for (int i = 0; i < NPAGES; i++) {
	    buf[i * PAGE_SIZE_4K] = i;
    }

    /* check */
    for (int i = 0; i < NPAGES; i++) {
	    assert(buf[i * PAGE_SIZE_4K] == i);
    }
}

static void
pt_test( void )
{
    /* need a decent sized stack */
    char buf1[NPAGES * PAGE_SIZE_4K], *buf2 = NULL;

    /* check the stack is above phys mem */
    assert((void *) buf1 > (void *) TEST_ADDRESS);

    /* stack test */
    do_pt_test(buf1);
    /* tty_debug_print("begion malloc\n"); */

    /* heap test */
    buf2 = malloc(NPAGES * PAGE_SIZE_4K);
    /* tty_debug_print("malloc 0x%x\n", buf2); */
    assert(buf2);
    do_pt_test(buf2);
    free(buf2);
}

int main(int argc, char** argv){
    /* initialise communication */
    /* int * p = (int*)(0x20001000U); */
    /* *p = 10000; */

    printf("task:\tHello world, I'm\ttty_test! argc: %d %p %p\n", argc, &argc);
    do_pt_test(buff);
    if (argc < 2)
    {
        printf ("my_app [sleep_second]\n");
        return -1;
    }
    pt_test();
    /* tty_debug_print("finish pt_test\n"); */

    /* sos_process_create(); */
    int i = 0;
    sleep(atoi(argv[1]));
    printf("bye: %d\n", sos_my_id());
    return 0;
}
