#include <iostream>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

typedef struct Meta_Data_t {

    size_t m_init_allocation;
    size_t m_requested_allocation;
    bool m_is_free;
    Meta_Data_t *m_next;

} Meta_Data;

enum BlockInfo {
    FREE_BLOCKS,
    FREE_BYTES,
    ALLOC_BLOCKS,
    ALLOC_BYTES
};

Meta_Data *global_list = NULL;
Meta_Data *global_list_init = NULL;

#define MAX_MALLOC_SIZE 100000000
#define META_SIZE       sizeof(Meta_Data)

void *malloc(size_t size) {

    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return NULL;
    }

    intptr_t increment = META_SIZE + size;

    // trying to use freed memory
    if (global_list_init != NULL) {
        global_list = global_list_init;
        while (global_list->m_next != NULL) {
            if (global_list->m_is_free && global_list->m_init_allocation >= size) {
                global_list->m_requested_allocation = size;
                global_list->m_is_free = false;
                return (void *) ((Meta_Data *) global_list + 1);
            }
            global_list = global_list->m_next;
        }

        if (global_list->m_is_free && global_list->m_init_allocation >= size) {
            global_list->m_requested_allocation = size;
            global_list->m_is_free = false;
            return (void *) ((Meta_Data *) global_list + 1);

        }
    }

    void *prev_program_break = sbrk(increment);

    // TODO Check for bugs here
    void *return_ptr = (void *) ((Meta_Data *) prev_program_break + 1);

    if (*(int *) prev_program_break < 0) {
        return NULL;
    }

    Meta_Data m = {size, size, false, NULL};

    // put in global list.
    if (global_list_init == NULL) {
        global_list = (Meta_Data *) prev_program_break;
        global_list_init = (Meta_Data *) prev_program_break;
    } else {
        global_list = global_list_init;
        while (global_list->m_next != NULL) {
            global_list = global_list->m_next;
        }
        global_list->m_next = (Meta_Data *) prev_program_break;
    }

    // put in heap area.
    *(Meta_Data *) (prev_program_break) = m;

    return return_ptr;

}

void *calloc(size_t num, size_t size) {

    void *ptr = malloc(size * num);
    if (ptr == NULL) {
        return NULL;
    }

    // set to zero
    memset(ptr, 0, size);
    return ptr;

}

void free(void *p) {
    if (p == NULL) {
        return;
    }

    Meta_Data *meta_beginning = ((Meta_Data *) p - 1);

    meta_beginning->m_is_free = true;

}

void *realloc(void *oldp, size_t size) {

    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return NULL;
    }

    if (oldp == NULL) {
        return malloc(size);
    }

    Meta_Data *meta_beginning = ((Meta_Data *) oldp - 1);

    // there is space in old place.
    if (meta_beginning->m_init_allocation >= size) {
        meta_beginning->m_requested_allocation = size;
        return (void *) ((Meta_Data *) meta_beginning + 1);
    }

    void *ptr = malloc(size);
    if (ptr == NULL) {
        return NULL;
    }

    // copy data.
    memcpy(ptr, oldp, meta_beginning->m_requested_allocation);

    // free old space.
    free(oldp);

    return ptr;

}

size_t _get_blocks_info(BlockInfo b) {
    if (global_list_init == NULL) {
        return 0;
    }

    size_t free_block_counter = 0;
    size_t free_bytes_counter = 0;
    size_t alloc_block_counter = 0;
    size_t alloc_bytes_counter = 0;

    global_list = global_list_init;
    while (global_list != NULL) {
        if (global_list->m_is_free) {
            free_block_counter++;
            free_bytes_counter += global_list->m_init_allocation;
        } else {
            alloc_block_counter++;
            alloc_bytes_counter += global_list->m_init_allocation;
        }
        global_list = global_list->m_next;
    }

    switch (b) {
        case FREE_BLOCKS  :
            return free_block_counter;
        case FREE_BYTES   :
            return free_bytes_counter;
        case ALLOC_BLOCKS :
            return alloc_block_counter;
        case ALLOC_BYTES  :
            return alloc_bytes_counter;

    }

}

size_t _num_free_blocks() {
    return _get_blocks_info(FREE_BLOCKS);
}

size_t _num_free_bytes() {
    return _get_blocks_info(FREE_BYTES);
}

size_t _num_allocated_blocks() {
    return _get_blocks_info(ALLOC_BLOCKS) + _get_blocks_info(FREE_BLOCKS);
}

size_t _num_allocated_bytes() {
    return _get_blocks_info(ALLOC_BYTES) + _get_blocks_info(FREE_BYTES);
}

size_t _num_meta_data_bytes() {
    return META_SIZE * (_num_allocated_blocks());
}

size_t _size_meta_data() {
    return META_SIZE;
}
