#include "pagetable.h"
#include "frametable.h"
#include "mapping.h"


#include <sys/debug.h>


static paddr_t entity_paddr(uint32_t entity)
{
    return entity & seL4_PAGE_MASK;
}
static bool _valid_page_addr(uint32_t addr)
{
    return IS_PAGE_ALIGNED(addr);
}

struct pagetable* kcreate_pagetable(void)
{

    struct pagetable* pt = malloc(sizeof (struct pagetable));
    if (pt == NULL)
    {
        ERROR_DEBUG("malloc pagetable return NULL\n");
        return NULL;
    }

    pt->pt_list = NULL;
    pt->page_dir = NULL;
    clear_sos_object(&pt->vroot);

    pt->page_dir = (void*)kframe_alloc();
    if (pt->page_dir == NULL)
    {
        ERROR_DEBUG( "frame_alloc page_dir return NULL\n");
        destroy_pagetable(pt);
        return NULL;
    }
    // i don't know the address. it doesn't matter.
    pt->vroot.cap = seL4_CapInitThreadPD;
    pt->alloc_func = kframe_alloc;
    pt->free_func = kframe_free;
    return pt;
}

struct pagetable* create_pagetable(void)
{
    struct pagetable* pt = malloc(sizeof (struct pagetable));
    if (pt == NULL)
    {
        ERROR_DEBUG("malloc pagetable return NULL\n");
        return NULL;
    }

    pt->pt_list = NULL;
    pt->page_dir = NULL;
    clear_sos_object(&pt->vroot);

    pt->page_dir = (void*)kframe_alloc(NULL);
    if (pt->page_dir == NULL)
    {
        ERROR_DEBUG( "frame_alloc page_dir return NULL\n");
        destroy_pagetable(pt);
        return NULL;
    }

    int ret = init_sos_object(&(pt->vroot), seL4_ARM_PageDirectoryObject, seL4_PageDirBits);
    if (ret != 0)
    {
        destroy_pagetable(pt);
        return NULL;
    }
    pt->alloc_func = uframe_alloc;
    pt->free_func = uframe_free;
    return pt;
}

void destroy_pagetable(struct pagetable* pt )
{
    if (pt == NULL)
    {
        return;
    }
    if (pt->page_dir != NULL)
    {
        for (int i = 0; i < LEVEL1_PAGE_ENTRY_COUNT; ++ i)
        {
            if (pt->page_dir[i] != NULL)
            {
                struct pagetable_entry* l1 = (pt->page_dir[i]);
                for (int j = 0; j < LEVEL2_PAGE_ENTRY_COUNT; ++ j)
                {
                    if (l1[j].entity != 0)
                    {
                        free_page(pt, seL4_PAGE_MASK & (l1[j].entity));
                    }
                }
                kframe_free((sos_vaddr_t)pt->page_dir[i]);
                pt->page_dir[i] = NULL;
            }
        }
        kframe_free((sos_vaddr_t)pt->page_dir);
        pt->page_dir = NULL;
    }
    if (pt->pt_list != NULL)
    {
        for (struct sel4_pagetable* it = pt->pt_list;
             it != NULL;
             )
        {
            my_unmap_page_table(&(it->sel4_pt));
            struct sel4_pagetable* tmp = it;
            it = it->next;
            free(tmp);
        }

    }
    free_sos_object(&(pt->vroot), seL4_PageDirBits);
    free(pt);
    return;
}

static uint32_t _get_pagetable_entry(struct pagetable* pt, vaddr_t vaddr)
{
    assert(pt != NULL);
    assert(_valid_page_addr(vaddr) );
    int l1_index = (vaddr & LEVEL1_PAGE_MASK) >> 22;
    int l2_index = (vaddr & LEVEL2_PAGE_MASK) >> 12;
    if (pt->page_dir == NULL)
    {
        return 0;
    }
    else if (pt->page_dir[l1_index] == NULL)
    {
        return 0;

    }
    return pt->page_dir[l1_index][l2_index].entity;
}

static int _insert_pagetable_entry(struct pagetable* pt, vaddr_t vaddr, paddr_t paddr)
{
    assert(pt != NULL);
    assert(_valid_page_addr(vaddr) && _valid_page_addr(paddr) );
    int l1_index = (vaddr & LEVEL1_PAGE_MASK) >> 22;
    int l2_index = (vaddr & LEVEL2_PAGE_MASK) >> 12;
    if (pt->page_dir == NULL)
    {
        return -1;
    }
    if (pt->page_dir[l1_index] == NULL)
    {
        pt->page_dir[l1_index] = (void*)kframe_alloc(NULL);
        if (pt->page_dir[l1_index]  == NULL)
        {
            return -2;
        }
    }
    assert(pt->page_dir[l1_index][l2_index].entity == 0);
    pt->page_dir[l1_index][l2_index].entity = paddr;
    return 0;
}

static void _insert_sel4_pt(struct pagetable* pt, struct sos_object* obj)
{
    assert(pt != NULL && obj->addr !=0 && obj->cap !=0);
    struct sel4_pagetable * p = malloc(sizeof (struct sel4_pagetable));
    assert(p != NULL);
    p->next = pt->pt_list;
    pt->pt_list = p;
    p->sel4_pt.addr = obj->addr;
    p->sel4_pt.cap = obj->cap;
    return;
}

void free_page(struct pagetable* pt, vaddr_t vaddr)
{
    assert(pt != NULL);
    vaddr &= seL4_PAGE_MASK;
    uint32_t entity = _get_pagetable_entry(pt, vaddr);
    if (entity == 0)
    {
        /* ERROR_DEBUG( "free_page vaddr 0x%x error\n", vaddr); */
        return;
    }
    assert(entity != 0 && (seL4_PAGE_MASK & entity ) != 0);
    paddr_t paddr = (entity & seL4_PAGE_MASK);
    seL4_CPtr app_cap = get_frame_app_cap(paddr);
    assert(app_cap != 0);
    // delete the app cap(memory)
    assert(0 == seL4_ARM_Page_Unmap(app_cap));
    assert(0 == cspace_delete_cap(cur_cspace, app_cap));
    set_frame_app_cap(paddr, 0);
    // then free the sos frame
    pt->free_func(paddr);
}

int alloc_page(struct pagetable* pt,
               vaddr_t vaddr,
               seL4_ARM_VMAttributes vm_attr,
               seL4_CapRights cap_right)
{
    assert(pt != NULL);
    vaddr &= seL4_PAGE_MASK;

    uint32_t entity = _get_pagetable_entry(pt, vaddr);
    assert(entity == 0);

    paddr_t paddr = pt->alloc_func(NULL);
    if (paddr == 0)
    {
        ERROR_DEBUG( "frame_alloc return NULL\n");
        return ENOMEM;
    }
    int ret = _insert_pagetable_entry(pt, vaddr, paddr);
    if (ret != 0)
    {
        pt->free_func(paddr);
        ERROR_DEBUG( "no enough mem for page table\n");
        return ENOMEM;
    }

    seL4_CPtr sos_cap = get_frame_sos_cap(paddr);
    if (sos_cap == 0)
    {
        pt->free_func(paddr);
        ERROR_DEBUG( "invalid frame table status!!!!!\n");
        return EINVAL;
    }
    seL4_CPtr app_cap = cspace_copy_cap(cur_cspace, cur_cspace, sos_cap, seL4_AllRights);
    if (app_cap == 0)
    {
        pt->free_func(paddr);
        ERROR_DEBUG( "cspace_copy_cap error\n");
        return ESEL4API;
    }

    /* ret = map_page(app_cap, pt->vroot.cap, vaddr, cap_right, vm_attr); */

    // map_page will leak sel4 pd
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
    assert(ret == 0);
    assert(0 == set_frame_app_cap(paddr, app_cap));
    return 0;
}

seL4_CPtr fetch_page_cap(struct pagetable* pt, vaddr_t vaddr)
{
    assert(pt != NULL);
    vaddr &= seL4_PAGE_MASK;

    uint32_t entity = _get_pagetable_entry(pt, vaddr);
    if (entity == 0)
    {
        return 0;
    }

    seL4_CPtr sos_cap = get_frame_sos_cap(entity_paddr(entity));
    if (sos_cap == 0)
    {
        ERROR_DEBUG( "get vaddr 0x%x cap error\n", vaddr);
        return 0;
    }
    return sos_cap;
}

paddr_t page_phys_addr(struct pagetable* pt, vaddr_t vaddr)
{
    assert(pt != NULL);
    vaddr &= seL4_PAGE_MASK;
    uint32_t entity = _get_pagetable_entry(pt, vaddr);
    return entity_paddr(entity);
}
