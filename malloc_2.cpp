#include <iostream>
#include <unistd.h>

typedef struct Meta_Data_t {

    size_t m_effective_allocation;
    bool m_is_free;
    Meta_Data_t *m_next;

} Meta_Data;

Meta_Data *global_list = NULL;

#define MAX_MALLOC_SIZE 100000000
#define META_SIZE       sizeof(Meta_Data)

void *malloc(size_t size) {

    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return NULL;
    }

    intptr_t increment = META_SIZE + size;
    void *prev_program_break = sbrk(increment);
                                            // TODO Check for bugs here
    void *return_ptr = (void*)((Meta_Data*)prev_program_break + 1);

    if (*(int *) prev_program_break < 0) {
        return NULL;
    }

    Meta_Data m = {size, false, NULL};

    // put in global list.
    if (global_list == NULL) {
        global_list = (Meta_Data *) prev_program_break;
    } else {
        while (global_list->m_next != NULL) {
            global_list = global_list->m_next;
        }
        global_list->m_next = (Meta_Data *) prev_program_break;
    }

    // put in heap area.
    *(Meta_Data*)(prev_program_break) = m;

    return return_ptr;

}
