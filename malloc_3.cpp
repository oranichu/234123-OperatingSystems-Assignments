#include <iostream>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

typedef struct Meta_Data_t {

    size_t m_init_allocation;
    size_t m_requested_allocation;
    bool m_is_free;
    Meta_Data_t *m_next;
    Meta_Data_t *m_prev;

} Meta_Data;

enum BlockInfo {
    FREE_BLOCKS,
    FREE_BYTES,
    ALLOC_BLOCKS,
    ALLOC_BYTES
};

Meta_Data *global_list = NULL;
void *global_list_init = NULL;
Meta_Data *global_list_end = NULL;

#define MAX_MALLOC_SIZE   100000000
#define META_SIZE         sizeof(Meta_Data)
#define LARGE_ENOUGH_SIZE 128

void _combineNext(Meta_Data* meta_beginning) {
    Meta_Data *next = meta_beginning->m_next;
    if (next != NULL) {
        if (next->m_is_free) {
            meta_beginning->m_init_allocation += META_SIZE + next->m_init_allocation;
            meta_beginning->m_next = next->m_next;
            if (next->m_next != NULL) {
                next->m_next->m_prev = meta_beginning;
            }
        }
    }
}

void _combinePrev(Meta_Data* meta_beginning){
    Meta_Data *prev = meta_beginning->m_prev;
    if (prev != NULL) {
        if (prev->m_is_free) {
            prev->m_init_allocation += META_SIZE + meta_beginning->m_init_allocation;
            prev->m_next = meta_beginning->m_next;
            if (meta_beginning->m_next != NULL) {
                meta_beginning->m_next->m_prev = prev;
            }
        }
    }
}

void *_split(Meta_Data *meta_beginning, size_t size) {

    size_t new_size = meta_beginning->m_init_allocation - size - META_SIZE;
    Meta_Data m = {new_size, new_size, true, meta_beginning->m_next, meta_beginning};
    meta_beginning->m_init_allocation = size;
    meta_beginning->m_requested_allocation = size;
    // put in heap area.
    char *split_ptr = (char *) meta_beginning + META_SIZE + size;
    *(Meta_Data *) (split_ptr) = m;
    // update pointers

    if (meta_beginning->m_next != NULL) {
        meta_beginning->m_next->m_prev =(Meta_Data *) split_ptr;
    }

    meta_beginning->m_next = (Meta_Data *) split_ptr;
    if (meta_beginning == global_list_end) { // splited part is wilderness
        global_list_end = (Meta_Data *) split_ptr;
    }

    _combineNext((Meta_Data*)split_ptr);
    return (void *) ((Meta_Data *) meta_beginning + 1);

}

void *malloc(size_t size) {

    switch (size % 4) { // aligning size.
        case 0:
            break;
        case 1:
            size += 3;
            break;
        case 2:
            size += 2;
            break;
        case 3:
            size += 1;
            break;
    }

    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return NULL;
    }

    intptr_t increment = META_SIZE + size;

    // trying to use freed memory
    if (global_list_init != NULL) {
        global_list = (Meta_Data *) global_list_init;
        while (global_list != NULL) {
            if (global_list->m_is_free && global_list->m_init_allocation >= size) {
                global_list->m_requested_allocation = size;
                global_list->m_is_free = false;

                // checks if size of block in large enough
                if (global_list->m_init_allocation - size - META_SIZE >= LARGE_ENOUGH_SIZE) {
                    // check if we have room in the splitable part for meta data.
                    if (global_list->m_init_allocation - size > META_SIZE) {
                        // split.
                        return _split(global_list, size);
                    }
                }

                return (void *) ((Meta_Data *) global_list + 1);
            }
            global_list = global_list->m_next;
        }
    }

    // no place in freed memory

    // check Wilderness chunk.
    if (global_list_init != NULL && global_list_end != NULL) {
        if (global_list_end->m_is_free) {
            // increase by diff
            void *prev_program_break = sbrk(size - global_list_end->m_init_allocation);
            if (*(int *) prev_program_break < 0) {
                return NULL;
            }
            // update sizes.
            global_list_end->m_init_allocation = size;
            global_list_end->m_requested_allocation = size;
            global_list_end->m_is_free = false;

            void *return_ptr = (void *) ((Meta_Data *) global_list_end + 1);
            return return_ptr;

        }
    }
    void *prev_program_break = sbrk(increment);

    void *return_ptr = (void *) ((Meta_Data *) prev_program_break + 1);

    if (*(int *) prev_program_break < 0) {
        return NULL;
    }

    Meta_Data m = {size, size, false, NULL, NULL};

    // put in global list.
    if (global_list_init == NULL) {
        global_list = (Meta_Data *) prev_program_break;
        global_list_init = prev_program_break;
    } else {
        global_list = (Meta_Data *) global_list_init;
        while (global_list->m_next != NULL) {
            global_list = global_list->m_next;
        }
        global_list->m_next = (Meta_Data *) prev_program_break;
        m.m_prev = global_list;
    }

    // put in heap area.
    *(Meta_Data *) (prev_program_break) = m;

    // update end of list.
    global_list_end = (Meta_Data *) prev_program_break;

    return return_ptr;

}

void *calloc(size_t num, size_t size) {

    void *ptr = malloc(size * num);
    if (ptr == NULL) {
        return NULL;
    }

    // set to zero
    memset(ptr, 0, size * num);
    return ptr;

}



void free(void *p) {
    if (p == NULL) {
        return;
    }

    Meta_Data *meta_beginning = ((Meta_Data *) p - 1);

    meta_beginning->m_is_free = true;

    _combineNext(meta_beginning);
    _combinePrev(meta_beginning);

}

void *realloc(void *oldp, size_t size) {

    switch (size % 4) { // aligning size.
        case 0:
            break;
        case 1:
            size += 3;
            break;
        case 2:
            size += 2;
            break;
        case 3:
            size += 1;
            break;
    }

    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return NULL;
    }

    if (oldp == NULL) {
        return malloc(size);
    }

    Meta_Data *meta_beginning = ((Meta_Data *) oldp - 1);

    // there is space in old place.
    if (meta_beginning->m_init_allocation >= size) {

        // check if splitable.
        if (meta_beginning->m_init_allocation - size - META_SIZE >= LARGE_ENOUGH_SIZE) {

            // check if we have room in the splitable part for meta data.
            if (meta_beginning->m_init_allocation - size > META_SIZE) {
                // split.
                return _split(meta_beginning, size);
            }
        }
        return (void *) ((Meta_Data *) meta_beginning + 1);

    }

    // realloc on wilderness.
    if (meta_beginning == global_list_end) {
        // check Wilderness chunk.
        // increase by diff
        void *prev_program_break = sbrk(size - global_list_end->m_init_allocation);
        if (*(int *) prev_program_break < 0) {
            return NULL;
        }
        // update sizes.
        global_list_end->m_init_allocation = size;
        global_list_end->m_requested_allocation = size;
        global_list_end->m_is_free = false;

        void *return_ptr = (void *) ((Meta_Data *) global_list_end + 1);
        return return_ptr;
    }

    // combine curr and next (if next is free)
    Meta_Data *meta_next = meta_beginning->m_next;

    if (meta_next->m_is_free) {
        size_t new_size =
                meta_beginning->m_init_allocation + META_SIZE + meta_next->m_init_allocation;
        if (new_size >= size) {
            // combine them
            meta_beginning->m_init_allocation = new_size;
            meta_beginning->m_requested_allocation = size;
            meta_beginning->m_next = meta_next->m_next;
            meta_next->m_next->m_prev = meta_beginning;

            // check if remaining part is splitable.
            if (meta_beginning->m_init_allocation - size - META_SIZE >= LARGE_ENOUGH_SIZE) {

                // check if we have room in the splitable part for meta data.
                if (meta_beginning->m_init_allocation - size > META_SIZE) {
                    // split.
                    return _split(meta_beginning, size);
                }
            }
            return (void *) ((Meta_Data *) meta_beginning + 1);
        }
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

    global_list = (Meta_Data *) global_list_init;
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
