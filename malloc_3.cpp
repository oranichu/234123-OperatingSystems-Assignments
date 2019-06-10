#include <iostream>
#include <unistd.h>
#include <string.h>
#include <cstdlib>
#include <assert.h>

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
Meta_Data *global_list_init = NULL;
Meta_Data *global_list_end = NULL;

#define MAX_MALLOC_SIZE   100000000
#define META_SIZE         sizeof(Meta_Data)
#define LARGE_ENOUGH_SIZE 128

void *malloc(size_t size) {

    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return NULL;
    }

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

    intptr_t increment = META_SIZE + size;

    // trying to use freed memory
    if (global_list_init != NULL) {
        global_list = global_list_init;
        while (global_list != NULL) {
            if (global_list->m_is_free && global_list->m_init_allocation >= size) {
                global_list->m_requested_allocation = size;
                global_list->m_is_free = false;

                // checks if size of block in large enough
                if (global_list->m_init_allocation - size - META_SIZE >= LARGE_ENOUGH_SIZE) {

                    // check if we have room in the splitable part for meta data.
                    if (global_list->m_init_allocation - size > META_SIZE) {
                        // split.
                        size_t new_size = global_list->m_init_allocation - size - META_SIZE;
                        Meta_Data m = {new_size, new_size, true, global_list->m_next, global_list};
                        global_list->m_init_allocation = size;

                        // put in heap area.
                        char *split_ptr = (char *) global_list + META_SIZE + size;
                        *(Meta_Data *) (split_ptr) = m;
                        global_list->m_next = (Meta_Data *) split_ptr;

                        if (global_list == global_list_end) { // splited part is wilderness
                            global_list_end = (Meta_Data *) split_ptr;
                        }
                    }
                }

                return (void *) ((Meta_Data *) global_list + 1);
            }
            global_list = global_list->m_next;
        }
    }

    // no place in freed memory

    // check Wilderness chunk.
    if (global_list_end != NULL) {
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

    // TODO Check for bugs here
    void *return_ptr = (void *) ((Meta_Data *) prev_program_break + 1);

    if (*(int *) prev_program_break < 0) {
        return NULL;
    }

    Meta_Data m = {size, size, false, NULL, NULL};

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
    memset(ptr, 0, size);
    return ptr;

}

void free(void *p) {
    if (p == NULL) {
        return;
    }

    Meta_Data *meta_beginning = ((Meta_Data *) p - 1);

    meta_beginning->m_is_free = true;

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

/*
int main() {

    global_list_init = NULL;
    global_list = NULL;

    assert(malloc(0) == NULL);
    assert(malloc(MAX_MALLOC_SIZE + 1) == NULL);

    // allocate 6 big blocks
    void *b1, *b2, *b3, *b4, *b5, *b6, *b7, *b8, *b9;
    b1 = malloc(1000);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 1);
    assert(_num_allocated_bytes() == 1000);
    assert(_num_meta_data_bytes() == META_SIZE);

    b2 = malloc(2000);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 3000);
    assert(_num_meta_data_bytes() == 2 * META_SIZE);

    b3 = malloc(3000);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 3);
    assert(_num_allocated_bytes() == 6000);
    assert(_num_meta_data_bytes() == 3 * META_SIZE);

    b4 = malloc(4000);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 4);
    assert(_num_allocated_bytes() == 10000);
    assert(_num_meta_data_bytes() == 4 * META_SIZE);

    b5 = malloc(5000);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 5);
    assert(_num_allocated_bytes() == 15000);
    assert(_num_meta_data_bytes() == 5 * META_SIZE);

    b6 = malloc(6000);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == 21000);
    assert(_num_meta_data_bytes() == 6 * META_SIZE);

    free(b3);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 3000);
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == 21000);
    assert(_num_meta_data_bytes() == 6 * META_SIZE);

    b3 = malloc(1000);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 3000 - META_SIZE - 1000);
    assert(_num_allocated_blocks() == 7);
    assert(_num_allocated_bytes() == 21000 - META_SIZE);
    assert(_num_meta_data_bytes() == 7 * META_SIZE);

    // free of b3 will combine two free blocks back together.
    free(b3);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 3000);
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == 21000);
    assert(_num_meta_data_bytes() == 6 * META_SIZE);

    // checking if free combine works on the other way.
    // (a a f a a a /free b4/ a a f f a a /combine b3 and b4/ a a f a a)
    free(b4);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 7000 + META_SIZE);
    assert(_num_allocated_blocks() == 5);
    assert(_num_allocated_bytes() == 21000 + META_SIZE);
    assert(_num_meta_data_bytes() == 5 * META_SIZE);

    // split will not work now, size is lower than 128 of data EXCLUDING the size of your meta-data structure.
    // the free block is of size 7000 + META_SIZE, so the splittable part is 127.
    b3 = malloc(7000 - 127);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 5);
    assert(_num_allocated_bytes() == 21000 + META_SIZE);
    assert(_num_meta_data_bytes() == 5 * META_SIZE);

    // free will work and combine.
    free(b3);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 7000 + META_SIZE);
    assert(_num_allocated_blocks() == 5);
    assert(_num_allocated_bytes() == 21000 + META_SIZE);
    assert(_num_meta_data_bytes() == 5 * META_SIZE);

    // split will work now, size is 128 of data EXCLUDING the size of your meta-data structure.
    // the free block is of size 7000 + META_SIZE, so the splittable part is 127.
    b3 = malloc(7000 - 128);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 128);
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == 21000);
    assert(_num_meta_data_bytes() == 6 * META_SIZE);

    // checking wilderness chunk
    free(b6);
    assert(_num_free_blocks() == 2);
    assert(_num_free_bytes() == 128 + 6000);
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == 21000);
    assert(_num_meta_data_bytes() == 6 * META_SIZE);

    // should take the middle block of size 128.
    b7 = malloc(128);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 6000);
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == 21000);
    assert(_num_meta_data_bytes() == 6 * META_SIZE);

    // should split wilderness block.
    b6 = malloc(5000);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 1000 - META_SIZE);
    assert(_num_allocated_blocks() == 7);
    assert(_num_allocated_bytes() == 21000 - META_SIZE);
    assert(_num_meta_data_bytes() == 7 * META_SIZE);

    // should enlarge wilderness block.
    b8 = malloc(1000);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 7);
    assert(_num_allocated_bytes() == 21000);
    assert(_num_meta_data_bytes() == 7 * META_SIZE);

    // add another block to the end.
    b9 = malloc(10);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 8);
    assert(_num_allocated_bytes() == 21012);
    assert(_num_meta_data_bytes() == 8 * META_SIZE);

    //
    free(b9);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 12);
    assert(_num_allocated_blocks() == 8);
    assert(_num_allocated_bytes() == 21012);
    assert(_num_meta_data_bytes() == 8 * META_SIZE);

    b9 = malloc(8);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 8);
    assert(_num_allocated_bytes() == 21012);
    assert(_num_meta_data_bytes() == 8 * META_SIZE);

    // checking alignment
    b9 = malloc(1);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 9);
    assert(_num_allocated_bytes() == 21016);
    assert(_num_meta_data_bytes() == 9 * META_SIZE);

    b9 = malloc(2);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 10);
    assert(_num_allocated_bytes() == 21020);
    assert(_num_meta_data_bytes() == 10 * META_SIZE);

    b9 = malloc(3);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 11);
    assert(_num_allocated_bytes() == 21024);
    assert(_num_meta_data_bytes() == 11 * META_SIZE);

    b9 = malloc(4);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 12);
    assert(_num_allocated_bytes() == 21028);
    assert(_num_meta_data_bytes() == 12 * META_SIZE);

    return 0;
}
*/