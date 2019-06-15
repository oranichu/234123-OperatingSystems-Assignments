#include <iostream>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

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

void malloc2_test_01() {
    // malloc
    int *ten = (int *) malloc(sizeof(int) * 10);
    assert(ten);
    for (int i = 0; i < 10; i++) {
        ten[i] = 10;
    }
    int *five = (int *) malloc(sizeof(int) * 5);
    assert(five);
    for (int i = 0; i < 5; i++) {
        five[i] = 5;
    }

    for (int i = 0; i < 10; i++) {
        assert(ten[i] == 10);
    }
    for (int i = 0; i < 5; i++) {
        assert(five[i] == 5);
    }

    // calloc
    int *three = (int *) calloc(3, sizeof(int));
    assert(three);
    for (int i = 0; i < 3; i++) {
        assert(three[i] == 0);
    }

    // helpers
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 3);
    assert(_num_allocated_bytes() == sizeof(int) * 18);
    assert(_num_meta_data_bytes() == _size_meta_data() * 3);

    // realloc
    int *ninety = (int *) realloc(ten, sizeof(int) * 90);
    for (int i = 0; i < 90; i++) {
        ninety[i] = 90;
    }
    assert(ninety);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(int) * 10);
    assert(_num_allocated_blocks() == 4);
    assert(_num_allocated_bytes() == sizeof(int) * 108);
    assert(_num_meta_data_bytes() == _size_meta_data() * 4);

    int *sixty = (int *) realloc(NULL, sizeof(int) * 60);
    assert(sixty);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(int) * 10);
    assert(_num_allocated_blocks() == 5);
    assert(_num_allocated_bytes() == sizeof(int) * 168);
    assert(_num_meta_data_bytes() == _size_meta_data() * 5);

    // order so far: ten(freed), five, three, ninety, sixty
    // free & malloc
    free(ninety);
    int *eleven = (int *) malloc(sizeof(int) * 11);
    assert(eleven == ninety);
    for (int i = 0; i < 11; i++) {
        eleven[i] = 11;
    }
    for (int i = 11; i < 90; i++) {
        assert(ninety[i] == 90);
    }

    // order so far: ten(freed), five, three, ninety(eleven), sixty
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(int) * 10);
    assert(_num_allocated_blocks() == 5);
    assert(_num_allocated_bytes() == sizeof(int) * 168);
    assert(_num_meta_data_bytes() == _size_meta_data() * 5);
}

size_t valid_free_blocks = 0;
size_t valid_free_bytes = 0;
size_t valid_allocated_blocks = 0;
size_t valid_allocated_bytes = 0;
size_t valid_meta_data_bytes = 0;

#define TEST_MALLOC() do {\
    assert(_num_free_blocks() == valid_free_blocks);\
    assert(_num_free_bytes() == valid_free_bytes);\
    assert(_num_allocated_blocks() == valid_allocated_blocks);\
    assert(_num_allocated_bytes() == valid_allocated_bytes);\
    assert(_num_meta_data_bytes() == valid_meta_data_bytes);\
    } while (0)

void malloc2_test_011() {

    // malloc
    int *ten = (int *) malloc(sizeof(int) * 10);
    assert(ten);
    for (int i = 0; i < 10; i++) {
        ten[i] = 10;
    }
    int *five = (int *) malloc(sizeof(int) * 5);
    assert(five);
    for (int i = 0; i < 5; i++) {
        five[i] = 5;
    }

    for (int i = 0; i < 10; i++) {
        assert(ten[i] == 10);
    }
    for (int i = 0; i < 5; i++) {
        assert(five[i] == 5);
    }

    // calloc
    int *three = (int *) calloc(3, sizeof(int));
    assert(three);
    for (int i = 0; i < 3; i++) {
        assert(three[i] == 0);
    }

    // helpers
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 3);
    assert(_num_allocated_bytes() == sizeof(int) * 18);
    assert(_num_meta_data_bytes() == _size_meta_data() * 3);

    // realloc
    int *ninety = (int *) realloc(ten, sizeof(int) * 90);
    for (int i = 0; i < 90; i++) {
        ninety[i] = 90;
    }
    assert(ninety);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(int) * 10);
    assert(_num_allocated_blocks() == 4);
    assert(_num_allocated_bytes() == sizeof(int) * 108);
    assert(_num_meta_data_bytes() == _size_meta_data() * 4);

    int *sixty = (int *) realloc(NULL, sizeof(int) * 60);
    assert(sixty);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(int) * 10);
    assert(_num_allocated_blocks() == 5);
    assert(_num_allocated_bytes() == sizeof(int) * 168);
    assert(_num_meta_data_bytes() == _size_meta_data() * 5);

    // order so far: ten(freed), five, three, ninety, sixty
    // free & malloc
    free(ninety);
    int *eleven = (int *) malloc(sizeof(int) * 11);
    assert(eleven == ninety);
    for (int i = 0; i < 11; i++) {
        eleven[i] = 11;
    }
    for (int i = 11; i < 90; i++) {
        assert(ninety[i] == 90);
    }

    // order so far: ten(freed), five, three, ninety(eleven), sixty
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(int) * 10);
    assert(_num_allocated_blocks() == 5);
    assert(_num_allocated_bytes() == sizeof(int) * 168);
    assert(_num_meta_data_bytes() == _size_meta_data() * 5);

}

int main() {

    global_list_init = NULL;
//Reuse a memory block if the size requested is smaller than the old block
    void *first_ptr = malloc(8);
    assert(first_ptr);
    void *second_ptr = realloc(first_ptr, 4);
    assert(second_ptr);
    assert(first_ptr == second_ptr);
    valid_allocated_blocks++;
    valid_allocated_bytes += 8;
    valid_meta_data_bytes += _size_meta_data();
    TEST_MALLOC();

    //Check that oldp is not freed if realloc fails
    void *third_ptr = realloc(second_ptr, 0);   //Fails because size==0
    assert(!third_ptr);
    assert(second_ptr);
    TEST_MALLOC();

    //Check everything still makes sense
    free(second_ptr);
    valid_free_blocks++;
    valid_free_bytes += 8;
    TEST_MALLOC();


    /*******************************************
    This part onwards differs from malloc_3:
    ********************************************/

    //Test realloc for a large block
    int *large_malloc = (int *) malloc(40 * sizeof(int));
    assert(large_malloc);
    for (int i = 0; i < 40; i++) {
        large_malloc[i] = i;
    }
    valid_allocated_blocks++;
    valid_allocated_bytes += 40 * sizeof(int);
    valid_meta_data_bytes += _size_meta_data();
    TEST_MALLOC();

    //Should create a new block and free the old one - without wilderness increase
    int *old_large_malloc = large_malloc;
    large_malloc = (int *) realloc(large_malloc, 100 * sizeof(int));
    assert(large_malloc);
    assert (large_malloc != old_large_malloc);
    for (int i = 0; i < 40; i++) {
        assert(large_malloc[i] == i);
    }
    valid_free_blocks++;
    valid_free_bytes += 40 * sizeof(int);
    valid_allocated_blocks++;
    valid_allocated_bytes += 100 * sizeof(int);
    valid_meta_data_bytes += _size_meta_data();
    TEST_MALLOC();

    //Check that failure for large block realloc dosen't make any changes (no free)
    int *failed_realloc = (int *) realloc(large_malloc, 0);
    assert(!failed_realloc);
    assert(large_malloc);
    for (int i = 0; i < 40; i++) {
        assert(large_malloc[i] == i);
    }
    TEST_MALLOC();

    //Should not split any blocks but still reuse the block
    large_malloc = (int *) realloc(large_malloc, 60 * sizeof(int));
    assert(large_malloc);
    for (int i = 0; i < 40; i++) {
        assert(large_malloc[i] == i);
    }
    TEST_MALLOC();

    global_list_init = NULL;
    malloc2_test_011();

    printf("Success for remalloc test: %d.\n", 2);

}
