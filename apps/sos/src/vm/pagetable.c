#include "pagetable.h"
#include "frametable.h"
#include "mapping.h"
#include <sys/debug.h>

// static bool _valid_page_addr(uint32_t addr)
// {
//     return IS_PAGE_ALIGNED(addr);
// }
#define LEVEL1_PAGE_ENTRY_COUNT (1024)
#define LEVEL1_PAGE_MASK        (0xFFC00000)
#define LEVEL2_PAGE_ENTRY_COUNT (1024)
#define LEVEL2_PAGE_MASK        (0x003FF000)

struct pagetable* create_pagetable(void) {
	struct pagetable * pagetb = (struct pagetable *)malloc(sizeof(struct pagetable));

	if(pagetb == NULL) {
		ERROR_DEBUG("malloc pagetable return NULL\n");
        return NULL;
	}

	pagetb->pt_list = NULL;
	pagetb->page_dir = NULL;

	clear_sos_object(&pagetb->vroot);

	pagetb->page_dir = (void*)frame_alloc(NULL); // the first level pagetable

	if (pagetb->page_dir == NULL) {
		ERROR_DEBUG( "frame_alloc page_dir return NULL\n");
        destroy_pagetable(pagetb);
        return NULL;
	}

	int ret = init_sos_object(&(pagetb->vroot), seL4_ARM_PageDirectoryObject, seL4_PageDirBits);

	if (ret != 0) {
		destroy_pagetable(pagetb);
		return NULL;
	}

	return pagetb;
}


void destroy_pagetable(struct pagetable* pt) {

}


static uint32_t _get_pagetable_entry(struct pagetable* pt, vaddr_t vaddr) {
	assert(pt != NULL);
	// assert(vaddr != NULL);
	int l1_index = (vaddr & LEVEL1_PAGE_MASK) >> 22;
	int l2_index = (vaddr & LEVEL2_PAGE_MASK) >> 12;

	if (pt->page_dir == NULL) {
		return 0;
	} else if (pt->page_dir[l1_index] == NULL) {
		return 0;
	}

	return pt->page_dir[l1_index][l2_index];
}

static int _insert_pagetable_entry(struct pagetable* pt, vaddr_t vaddr, paddr_t paddr) {
	assert(pt != NULL);

	if (pt->page_dir == NULL) {
		return -1; // page table does not exist
	}

	int l1_index = (vaddr & LEVEL1_PAGE_MASK) >> 22;
	int l2_index = (vaddr & LEVEL2_PAGE_MASK) >> 12;

	if(pt->page_dir[l1_index] == NULL) {
		pt->page_dir[l1_index] = (void *)frame_alloc(NULL);
		if (pt->page_dir[l1_index] == NULL) {
			return -2;
		}
	}

	assert(pt->page_dir[l1_index][l2_index].entity == 0);
	pt->page_dir[l1_index][l2_index].entity = paddr; // paddr will certainly be page-aligned, since this is
													 // returned by frame_alloc

	return 0;
}

static void _insert_sel4_pt(struct pagetable* pt, struct sos_object* obj)
{
    assert(pt != NULL && obj->addr !=0 && obj->cap !=0);
    struct sel4_pagetable_entry * p = malloc(sizeof (struct sel4_pagetable_entry));
    assert(p != NULL);
    p->next = pt->pt_list;
    pt->pt_list = p;
    p->sel4_pt.addr = obj->addr;
    p->sel4_pt.cap = obj->cap;
    return;
}

int alloc_page(struct pagetable* pt,
    vaddr_t vaddr,
    seL4_ARM_VMAttributes vm_attr,
    seL4_CapRights cap_right) {

	assert(pt != NULL);
	// assert(vaddr != NULL);

	vaddr &= seL4_PAGE_MASK;

	uint32_t entity = _get_pagetable_entry(pt, vaddr);
    assert(entity == 0);

    paddr_t paddr = frame_alloc(NULL);
    if (paddr == 0) {
    	ERROR_DEBUG( "frame_alloc return NULL\n");
        return ENOMEM;
    }

    int ret = _insert_pagetable_entry(pt, vaddr, paddr);
    if (ret != 0)
    {
        frame_free(paddr);
        ERROR_DEBUG( "no enough mem for page table\n");
        return ENOMEM;
    }

	seL4_CPtr sos_cap = get_frame_sos_cap(paddr);
    if (sos_cap == 0)
    {
        frame_free(paddr);
        ERROR_DEBUG( "invalid frame table status!!!!!\n");
        return EINVAL;
    }
    seL4_CPtr app_cap = cspace_copy_cap(cur_cspace, cur_cspace, sos_cap, seL4_AllRights);    

    if (app_cap == 0)
    {
        frame_free(paddr);
        ERROR_DEBUG( "cspace_copy_cap error\n");
        return ESEL4API;
    }

    ret = seL4_ARM_Page_Map(app_cap, pt->vroot.cap, vaddr, cap_right, vm_attr);
    if(ret == seL4_FailedLookup)
    {
        /* Assume the error was because we have no page table in sel4 kernel.*/
        struct sos_object sel4_pt;
        clear_sos_object(&sel4_pt);
        ret = map_page_table(pt->vroot.cap, vaddr, &sel4_pt);

        assert(ret == 0);
        if(!ret)
        {
            int ret = seL4_ARM_Page_Map(app_cap, pt->vroot.cap, vaddr, cap_right, vm_attr);
            assert(ret == 0);
        }
        _insert_sel4_pt(pt, &sel4_pt);
    }
}

void free_page(struct pagetable* pt, vaddr_t vaddr) {

}
