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
void *global_list_init = NULL;
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
        global_list = (Meta_Data*)global_list_init;
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

    // TODO Check for bugs here
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
        global_list = (Meta_Data*)global_list_init;
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

    global_list = (Meta_Data*)global_list_init;
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

void oran() {
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
}

void malloc3_test_01() {
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
    for (int i = 0; i < 10; i++) {
        assert(ninety[i] == 10);
    }
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
    assert(eleven >= ninety);
    assert(eleven <= (void *) ((long) ninety + 79 * sizeof(int)));

    for (int i = 0; i < 11; i++) {
        eleven[i] = 11;
    }
    for (int i = 11 + _size_meta_data() * sizeof(int); i < 90; i++) {
        assert(ninety[i] == 90);
    }

    // order so far: freed(10), five, three, eleven, freed(79-data_size), sixty
    assert(_num_free_blocks() == 2);
    assert(_num_free_bytes() == sizeof(int) * (10 + 79) - _size_meta_data());
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == sizeof(int) * 168 - _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 6);

    int *old_ten = ten;
    ten = (int *) malloc(sizeof(int) * 10);
    assert(ten == old_ten);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(int) * 79 - _size_meta_data());
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == sizeof(int) * 168 - _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 6);
    // order so far: ten, five, three, eleven, freed(79-data_size), sixty

}

void malloc3_test_02() {
    long long *tens[11];

    for (int i = 10; i < 101; i += 10) {
        tens[i / 10] = (long long *) malloc(sizeof(long long) * i);
    }
    for (int i = 1; i < 11; i++) {
        for (int j = 0; j < i; j++) {
            tens[i][j] = j;
        }
    }
    for (int i = 1; i < 11; i++) {
        for (int j = 0; j < i; j++) {
            assert(tens[i][j] == j);
        }
    }

    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 10);
    assert(_num_allocated_bytes() == sizeof(long long) * 550);
    assert(_num_meta_data_bytes() == _size_meta_data() * 10);

    free(tens[5]);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(long long) * 50);
    assert(_num_allocated_blocks() == 10);
    assert(_num_allocated_bytes() == sizeof(long long) * 550);
    assert(_num_meta_data_bytes() == _size_meta_data() * 10);

    for (int i = 1; i < 11; i++) {
        if (i != 5 && i != 8) free(tens[i]);
    }
    // order: free(280+6*data), 80, free(190+data)
    assert(_num_free_blocks() == 2);
    assert(_num_free_bytes() ==
           sizeof(long long) * 470 + 7 * _size_meta_data());
    assert(_num_allocated_blocks() == 3);
    assert(_num_allocated_bytes() ==
           sizeof(long long) * 550 + 7 * _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 3);

    free(tens[8]);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() ==
           sizeof(long long) * 550 + 9 * _size_meta_data());
    assert(_num_allocated_blocks() == 1);
    assert(_num_allocated_bytes() ==
           sizeof(long long) * 550 + 9 * _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 1);

}

void malloc3_test_03() {
    assert(_num_meta_data_bytes() % 4 == 0); // problem 3 check

    void *huge = (void *) malloc(1000);
    assert(huge);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 1);
    assert(_num_allocated_bytes() == 1000);
    assert(_num_meta_data_bytes() == _size_meta_data() * 1);
    void *tiny = (void *) malloc(31); // (problem 4)
    free(huge);
    assert(tiny);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 1000);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1032);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);

    // fits just right (problem 1 test for exactly 128 free bytes is okay for split)
    void *mid = (void *) malloc(1000 - 128 - _size_meta_data());
    assert(mid >= huge && mid <= (void *) ((long) huge + 872));
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 128);
    assert(_num_allocated_blocks() == 3);
    assert(_num_allocated_bytes() == 1032 - _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 3);

    free(mid); // free place should unite problem 2 and become 1000 again
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 1000);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1032);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);

    // doesnt fit (problem 1 test for exactly 124 free bytes shouldn't split)
    mid = (void *) malloc(1000 - 124 - _size_meta_data());
    assert(mid == huge);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1032);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);

    free(tiny); // a wilderness block (problem 3)
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 32);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1032);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);

    tiny = (void *) malloc(33); // (problem 3)
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1036);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);
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


void remalloc_3_test() {
    //Reuse a memory block if the size requested is smaller than the old block
    void* first_ptr = malloc(8);
    assert(first_ptr);
    void* second_ptr = realloc(first_ptr, 4);
    assert(second_ptr);
    assert(first_ptr == second_ptr);
    valid_allocated_blocks++;
    valid_allocated_bytes+=8;
    valid_meta_data_bytes+=_size_meta_data();
    TEST_MALLOC();

    //Check that oldp is not freed if realloc fails
    void* third_ptr = realloc(second_ptr, 0);   //Fails because size==0
    assert(!third_ptr);
    assert(second_ptr);
    TEST_MALLOC();

    //Check everything still makes sense
    free(second_ptr);
    valid_free_blocks++;
    valid_free_bytes+=8;
    TEST_MALLOC();


    /*******************************************
    This part onwards differs from malloc_2:
    ********************************************/

    //Test realloc for a large block
    int* large_malloc = (int*)malloc(40*sizeof(int));   //Increases wilderness
    assert(large_malloc);
    for (int i = 0; i < 40; i++) {
        large_malloc[i] = i;
    }
    valid_free_blocks--;
    valid_free_bytes-=8;
    valid_allocated_bytes += (40*sizeof(int)-8);
    TEST_MALLOC();

    //Should increase the wilderness further
    int* old_large_malloc = large_malloc;
    large_malloc = (int*)realloc(large_malloc, 100*sizeof(int));
    assert(large_malloc);
    assert (large_malloc == old_large_malloc);
    for (int i = 0; i < 40; i++) {
        assert(large_malloc[i] == i);
    }
    valid_allocated_bytes = 100*sizeof(int);
    TEST_MALLOC();

    //Check that failure for large block realloc dosen't make any changes (Without uniting any blocks)
    int* failed_realloc = (int*)realloc(large_malloc, 0);
    assert(!failed_realloc);
    assert(large_malloc);
    for (int i = 0; i < 40; i++) {
        assert(large_malloc[i] == i);
    }
    TEST_MALLOC();

    //Should split the block
    large_malloc = (int*)realloc(large_malloc, 60*sizeof(int));
    assert(large_malloc);
    for (int i = 0; i < 40; i++) {
        assert(large_malloc[i] == i);
    }
    valid_free_blocks++;
    valid_free_bytes += 40*sizeof(int)-_size_meta_data();
    valid_allocated_blocks++;
    valid_allocated_bytes-=_size_meta_data();
    valid_meta_data_bytes+=_size_meta_data();
    TEST_MALLOC();
}

void malloc3_test_011() {

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
    for (int i = 0; i < 10; i++) {
        assert(ninety[i] == 10);
    }
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
    assert(eleven >= ninety);
    assert(eleven <= (void *) ((long) ninety + 79 * sizeof(int)));

    for (int i = 0; i < 11; i++) {
        eleven[i] = 11;
    }
    for (int i = 11 + _size_meta_data() * sizeof(int); i < 90; i++) {
        assert(ninety[i] == 90);
    }

    // order so far: freed(10), five, three, eleven, freed(79-data_size), sixty
    assert(_num_free_blocks() == 2);
    assert(_num_free_bytes() == sizeof(int) * (10 + 79) - _size_meta_data());
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == sizeof(int) * 168 - _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 6);

    int *old_ten = ten;
    ten = (int *) malloc(sizeof(int) * 10);
    assert(ten == old_ten);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(int) * 79 - _size_meta_data());
    assert(_num_allocated_blocks() == 6);
    assert(_num_allocated_bytes() == sizeof(int) * 168 - _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 6);
    // order so far: ten, five, three, eleven, freed(79-data_size), sixty

}

void malloc3_test_021() {

    long long *tens[11];

    for (int i = 10; i < 101; i += 10) {
        tens[i / 10] = (long long *) malloc(sizeof(long long) * i);
    }
    for (int i = 1; i < 11; i++) {
        for (int j = 0; j < i; j++) {
            tens[i][j] = j;
        }
    }
    for (int i = 1; i < 11; i++) {
        for (int j = 0; j < i; j++) {
            assert(tens[i][j] == j);
        }
    }

    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 10);
    assert(_num_allocated_bytes() == sizeof(long long) * 550);
    assert(_num_meta_data_bytes() == _size_meta_data() * 10);

    free(tens[5]);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == sizeof(long long) * 50);
    assert(_num_allocated_blocks() == 10);
    assert(_num_allocated_bytes() == sizeof(long long) * 550);
    assert(_num_meta_data_bytes() == _size_meta_data() * 10);

    for (int i = 1; i < 11; i++) {
        if (i != 5 && i != 8) free(tens[i]);
    }
    // order: free(280+6*data), 80, free(190+data)
    assert(_num_free_blocks() == 2);
    assert(_num_free_bytes() ==
           sizeof(long long) * 470 + 7 * _size_meta_data());
    assert(_num_allocated_blocks() == 3);
    assert(_num_allocated_bytes() ==
           sizeof(long long) * 550 + 7 * _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 3);

    free(tens[8]);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() ==
           sizeof(long long) * 550 + 9 * _size_meta_data());
    assert(_num_allocated_blocks() == 1);
    assert(_num_allocated_bytes() ==
           sizeof(long long) * 550 + 9 * _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 1);

}

void malloc3_test_031() {

    assert(_num_meta_data_bytes() % 4 == 0); // problem 3 check

    void *huge = (void *) malloc(1000);
    assert(huge);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 1);
    assert(_num_allocated_bytes() == 1000);
    assert(_num_meta_data_bytes() == _size_meta_data() * 1);
    void *tiny = (void *) malloc(31); // (problem 4)
    free(huge);
    assert(tiny);
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 1000);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1032);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);

    // fits just right (problem 1 test for exactly 128 free bytes is okay for split)
    void *mid = (void *) malloc(1000 - 128 - _size_meta_data());
    assert(mid >= huge && mid <= (void *) ((long) huge + 872));
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 128);
    assert(_num_allocated_blocks() == 3);
    assert(_num_allocated_bytes() == 1032 - _size_meta_data());
    assert(_num_meta_data_bytes() == _size_meta_data() * 3);

    free(mid); // free place should unite problem 2 and become 1000 again
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 1000);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1032);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);

    // doesnt fit (problem 1 test for exactly 124 free bytes shouldn't split)
    mid = (void *) malloc(1000 - 124 - _size_meta_data());
    assert(mid == huge);
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1032);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);

    free(tiny); // a wilderness block (problem 3)
    assert(_num_free_blocks() == 1);
    assert(_num_free_bytes() == 32);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1032);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);

    tiny = (void *) malloc(33); // (problem 3)
    assert(_num_free_blocks() == 0);
    assert(_num_free_bytes() == 0);
    assert(_num_allocated_blocks() == 2);
    assert(_num_allocated_bytes() == 1036);
    assert(_num_meta_data_bytes() == _size_meta_data() * 2);
}

// Malloc many bytes, play with values, and
void malloc_bytes_comparison_stress_test() {
#define NUMBER_OF_TESTS 4000
#define MAX_BLOCK_SIZE 600
#define NUM_OF_BLOCKS_TO_FREE 1000
    // We can't randomize using c++ because then we need to import the library which contains malloc. Try
    // Try if you want :)
    char random_bytes[NUMBER_OF_TESTS] = {92,93,-108,-46,-117,-33,-68,-27,-53,29,106,-60,24,87,-29,116,-64,2,25,73,-23,53,30,-40,-72,69,13,8,-82,-121,56,-61,-107,-55,57,-36,4,-92,31,-50,12,-15,-105,-104,-65,-121,118,96,27,-58,118,45,53,29,-87,116,55,-32,14,113,106,-36,75,-9,90,82,-94,64,62,-32,-117,-15,36,107,-19,-115,-47,77,-70,32,-5,-91,105,-75,32,-11,94,-81,121,-96,-46,-23,-6,99,30,-11,-94,-112,-65,-14,93,109,116,0,65,-52,79,-10,-26,50,-123,106,-9,-1,82,24,-53,-61,18,63,98,-110,61,77,123,39,-116,106,97,-46,51,39,51,-94,11,127,-44,112,-15,47,-38,-14,-11,-57,-39,-32,80,112,114,-54,6,-107,103,-94,-61,37,2,-53,47,47,-88,88,104,103,-101,-105,124,9,81,61,-88,111,-3,8,-4,-17,-93,60,23,-80,-68,-71,25,10,56,119,53,120,63,-81,-74,-80,-69,75,56,-37,121,-57,-53,65,71,12,47,-28,11,123,-1,-50,43,-57,-4,-94,29,84,-118,-20,28,111,-84,-101,-14,48,-34,108,-119,-97,-121,-34,48,-31,0,-40,66,92,103,-122,-14,-70,91,-32,14,56,103,-115,67,15,-110,126,-78,29,-57,66,-97,99,-8,-122,109,64,84,117,-92,99,92,-110,-83,-3,-66,101,-12,-83,-36,105,-45,-26,-42,-93,-40,74,37,6,-80,13,-2,102,-81,-26,-109,-71,11,-97,-106,24,-91,30,-60,-23,-25,52,96,-83,-2,-113,-45,-30,17,-69,106,108,-59,-33,-117,24,39,-17,-67,-54,-100,-22,-31,-91,-116,-71,-2,78,-22,-59,83,-20,100,-59,-6,-104,-116,123,-31,-21,-12,103,-45,-107,-81,-121,1,-35,18,-2,-76,95,-108,103,50,56,-106,-65,101,113,35,112,-52,19,-57,25,-55,-71,32,-49,-8,-100,15,-109,-74,-22,91,83,-103,-12,114,57,-12,76,-125,-78,71,-87,-36,123,-96,99,-82,21,116,-72,57,-111,-95,-12,104,-61,106,6,-36,-100,94,37,-119,109,123,-88,120,7,127,43,-123,-77,-80,-110,-22,-66,-35,5,-92,81,48,-116,127,98,-34,-29,101,100,66,37,89,73,2,-60,59,-55,15,81,99,-121,-40,-92,-44,40,77,7,-35,16,69,-13,70,36,105,69,-14,121,-27,-119,5,64,-29,-113,82,111,118,113,-34,7,91,-74,95,-60,117,-45,122,120,51,-64,1,-65,-106,20,61,-95,-87,99,-24,-94,80,-96,59,7,72,92,54,-63,97,-45,-41,-40,-57,-16,13,-22,-13,-25,91,-117,-28,36,115,69,115,-100,-16,-125,80,-30,101,113,79,97,1,-2,109,-49,-41,93,89,37,-90,-107,-99,2,-19,60,28,-17,41,71,73,-49,2,39,78,38,-35,-27,52,57,110,59,-43,18,-84,59,35,-53,-23,-35,23,0,23,-113,-31,-3,-79,-52,80,13,85,-12,51,-57,14,46,116,-16,106,-22,108,-122,-25,82,-128,-75,-86,56,45,-76,-79,111,74,2,16,20,13,-50,120,-108,-74,90,55,-78,-78,125,74,-114,58,81,20,26,4,83,-2,108,-100,122,-35,-62,40,94,117,-115,-55,73,68,4,98,-98,-48,-32,-115,8,60,-4,126,-48,-5,38,35,-40,61,43,-106,53,-112,123,-106,-83,-92,-55,12,-2,-111,117,22,-31,91,-18,-24,-128,-1,85,52,-36,67,110,-92,0,-10,-100,66,23,-79,-95,-71,-66,103,-32,102,-53,-67,72,106,-122,91,-98,80,5,-112,-6,-47,-64,-113,-41,-13,50,127,18,-56,104,66,81,33,104,56,-21,-107,-30,-116,79,10,-92,25,55,-19,-117,-26,10,-24,7,114,-30,103,72,71,-5,80,106,80,54,98,74,99,-36,-66,98,-28,12,50,-60,94,23,-53,90,-3,0,1,-20,-12,105,-78,-124,56,68,-76,-117,38,-126,121,-94,78,-35,65,-86,-28,74,-31,111,-51,92,120,82,112,52,1,94,59,-71,-78,113,-68,-30,-74,-119,103,86,68,-30,-103,-73,-17,-62,-90,-57,-108,81,-93,-29,-127,77,113,27,79,-4,-76,-58,41,29,-82,-37,79,-91,24,30,-78,-104,79,-34,111,105,116,-45,25,68,18,20,51,68,101,62,81,-54,35,14,58,-98,-29,82,71,-55,-115,39,-35,-37,77,58,-59,-21,32,118,33,91,-29,35,-118,-75,-126,-53,-103,-88,-109,98,-73,-28,111,-61,-47,13,-27,27,14,122,52,-41,-3,-85,-103,61,101,-57,47,93,-44,63,24,68,67,67,95,107,110,-103,-112,104,-71,51,-36,-22,-3,121,23,45,73,98,92,-2,98,30,125,-118,7,96,-93,67,101,113,-3,-79,14,-109,-89,-99,-46,-50,-9,91,-70,-62,-76,-105,-22,-4,103,-94,-52,-39,-115,-73,-32,14,-34,103,-14,16,31,-117,-104,20,77,58,90,98,39,-68,88,43,75,-7,-118,83,86,-106,-24,76,-34,-115,-91,64,-17,40,-89,-125,-102,124,91,99,2,20,69,-24,-84,68,-36,61,31,-76,-88,-88,89,32,-114,-50,25,101,90,25,-42,59,-62,103,113,-103,61,-32,-13,113,-125,74,80,-38,-58,-21,93,62,-64,-32,117,75,-106,-82,44,-48,34,-37,-111,-114,108,84,70,65,74,-44,-81,-36,-59,-29,-128,52,72,61,-20,32,-127,84,-33,-89,-94,-114,-51,-106,-14,-122,88,100,83,37,-126,15,-46,100,-66,-45,126,-127,-50,-78,101,117,-99,125,-63,95,106,-11,-56,-114,-126,103,95,117,-67,54,52,-97,41,117,-15,33,-120,69,-35,-43,5,-15,121,-95,116,105,57,-96,27,99,43,-123,-70,-97,-118,-39,-60,-78,-107,122,124,93,-116,-124,19,-28,-23,-9,-62,113,-56,-62,16,-124,100,103,90,-42,-99,5,94,-126,-6,-68,64,78,82,-24,-69,-19,113,77,-122,-80,-68,-104,-119,92,51,80,-20,49,-23,34,79,99,-20,67,-30,-33,53,-22,-16,104,-42,115,-1,123,-8,-31,-47,86,-110,-2,80,-37,68,-98,32,-120,-67,-114,-68,-52,-74,18,28,-114,106,15,56,109,-103,33,65,-3,-94,-48,-65,-36,-104,2,30,-17,-44,84,-112,74,69,69,102,-53,55,72,-93,2,-27,-124,-95,100,94,19,-31,69,121,-29,-81,-21,52,-34,-80,-123,64,-117,122,-65,-79,1,117,-124,0,88,83,116,74,-113,-62,-85,-26,98,39,127,-66,107,12,61,79,-18,-81,125,-15,64,-2,8,101,-50,-68,20,-67,-105,84,49,103,83,96,102,-119,-59,-15,-103,68,-39,35,-122,19,86,118,75,93,-76,-95,37,92,-7,-43,48,-76,40,39,40,-3,9,-16,18,100,-65,-27,56,-104,-122,71,-47,-80,19,16,50,-84,-42,41,-72,-81,-116,-31,2,2,86,-31,107,125,121,67,-99,-5,127,39,-96,-27,-54,66,-50,77,-75,61,52,-16,-106,109,-49,-118,-10,119,-122,125,-103,41,-87,65,103,68,-11,105,124,17,89,7,-89,125,40,16,56,9,7,0,31,-81,-22,89,64,-80,80,31,-63,4,14,-55,47,121,111,126,21,31,-98,-14,-10,-29,-36,-123,-101,-60,49,114,18,96,120,111,-112,-105,13,36,108,73,106,-102,-14,25,-125,-84,122,50,14,-122,-106,-73,25,20,73,-117,79,65,48,-128,-120,-6,-68,-68,-127,-95,14,-10,0,36,-44,45,-80,6,-94,-53,-60,87,-52,35,105,7,-118,77,25,-11,-67,-4,-8,57,-89,-85,-99,-36,-48,76,125,10,-121,-71,-45,-39,86,73,-29,82,105,-12,21,102,64,-83,20,-37,-98,92,28,10,29,4,-51,-29,-5,55,69,61,31,59,99,-8,-76,57,118,69,73,-123,-91,-44,-93,42,-35,-29,-8,2,-59,45,-95,-70,-36,59,-66,91,-39,-99,-49,66,106,-90,117,-95,-77,-75,-74,-42,39,-124,51,10,-103,120,58,-49,19,50,-67,-28,49,-90,90,65,3,-44,-94,-59,-21,-32,-71,-3,40,-28,-121,2,-95,126,92,-60,-102,0,-69,-52,101,-14,-101,-4,-3,86,-51,48,-81,86,-127,-68,51,30,31,73,52,-54,62,-97,-39,-72,-102,42,-113,69,37,-12,20,80,-56,112,20,-21,-103,96,-71,-94,-124,109,-11,-106,83,51,-75,-123,-118,-6,50,-36,4,-5,-3,68,33,-26,12,-113,76,-68,115,19,46,-48,-14,-51,109,-56,75,62,112,15,103,-93,-123,74,-22,-80,-39,-69,-57,-46,50,89,-91,117,-96,-55,104,99,-1,-109,-48,-126,-121,67,-65,-120,-34,1,0,-104,-93,-68,110,-94,12,67,57,-102,16,120,108,-10,-105,-36,103,100,82,1,-115,84,98,-9,-16,-106,-72,37,100,1,-115,15,12,86,112,22,105,82,3,-54,99,-24,-69,-127,44,81,60,86,-118,62,81,119,-92,88,109,81,123,127,54,-13,-92,58,98,-30,49,79,-123,58,-120,-62,118,-77,-126,3,70,41,-65,117,0,13,-22,123,-81,105,56,-113,49,-95,106,-112,-49,40,83,-50,66,92,-79,5,110,-126,-55,69,39,118,-91,-28,-16,-50,-53,-116,124,-29,24,-32,68,-58,-45,-22,14,-40,-90,13,-74,-34,-38,43,-119,-30,-31,-84,-108,94,-85,52,2,118,-24,19,110,-40,9,73,111,-84,-93,47,123,-123,-10,14,-102,79,53,-69,18,-1,69,31,-112,47,26,120,-55,-71,118,-95,-99,-116,51,77,105,120,-111,40,4,-53,-30,-29,-106,100,39,67,-60,36,125,34,46,-72,4,95,45,-97,39,86,65,78,43,53,67,-79,-126,47,97,-15,111,-78,-25,86,-78,-84,-15,120,56,102,-114,65,-57,-109,-89,-113,101,-22,-76,-127,103,58,-75,116,-117,95,31,94,8,58,25,12,-2,-119,-15,71,33,-18,47,-98,-119,-4,57,54,28,-29,-112,-96,-107,-116,-81,-101,38,53,30,37,40,111,80,78,-126,5,80,0,-57,-18,21,-58,-127,-21,93,-50,-32,-87,33,47,64,-125,-64,12,-73,-79,82,81,-120,-56,-123,-122,92,16,-78,97,-59,-47,34,-56,101,-15,4,81,74,-51,-53,-65,-84,-3,-55,60,27,97,-84,0,21,-89,-64,-83,-7,-58,51,-63,67,-12,22,119,34,-61,52,88,-117,68,-7,66,-102,43,-42,108,-16,75,38,-57,127,84,-38,89,-7,-120,-81,4,69,120,-71,121,19,52,94,-81,-38,60,105,-118,-71,-75,-102,126,25,92,-88,-14,-93,125,14,17,115,-51,62,-11,81,-86,-48,0,56,-42,-11,-110,36,-83,-10,-71,102,-61,-49,99,114,-30,-89,-106,-25,101,-69,-86,-119,-3,42,46,-35,106,6,-109,108,-120,39,-102,-88,-50,-116,-116,-73,-78,-105,-13,17,91,-51,56,25,-118,-9,-91,23,-7,6,16,-127,-13,-30,18,-54,26,66,-127,-75,85,-103,1,101,34,84,46,74,-104,93,50,-81,107,-67,-73,15,113,90,34,102,51,26,51,69,-80,-70,14,-96,101,89,63,53,-109,-79,47,-68,-98,-94,68,-25,65,-100,-20,91,-21,-80,-108,-109,110,-22,126,103,65,-80,55,-83,118,100,75,27,-35,72,-53,-117,22,-39,-60,127,-59,-69,87,-9,-45,-61,-72,-44,63,72,-77,-117,-72,48,29,89,-10,11,85,55,-70,-88,116,45,43,96,-40,114,81,62,-27,82,-110,-128,103,36,-60,-24,-20,114,22,12,-116,15,-120,-88,93,-124,-27,46,-11,-113,-85,127,-40,5,-83,-95,64,-45,120,-100,-115,49,122,-1,-6,72,-115,-98,-35,-104,73,-21,92,87,-52,89,-127,-43,-72,-54,68,-123,-9,-113,-127,-123,-76,116,86,-7,-77,-31,43,-89,45,-36,-117,36,52,45,16,55,116,40,-108,2,-73,21,-5,92,-103,-115,-84,-124,-27,102,90,60,18,7,8,107,-74,3,67,-116,-14,17,45,-87,-33,44,122,-90,-82,-1,-115,57,46,-4,60,-47,-48,76,-13,70,-39,38,-32,-123,-61,-82,35,118,64,11,12,125,20,124,112,26,120,127,-119,47,61,-99,118,62,-72,19,84,51,17,75,124,82,38,43,6,63,-59,-95,25,-53,-3,77,29,1,-98,26,4,31,-107,-51,19,118,93,-88,8,-5,0,16,20,112,-42,-68,27,-7,38,-2,108,-84,-59,11,-85,100,114,-29,120,109,17,34,94,-78,-46,34,127,-118,116,-104,-102,42,122,-45,-127,18,-19,-29,70,86,-102,-87,-22,35,36,-41,99,-41,48,-10,87,-68,59,-87,72,-123,118,-75,117,25,-45,-124,-77,97,-104,116,-118,25,-29,126,-13,-93,57,45,-11,-15,95,85,40,47,99,-39,88,101,-61,49,47,-100,-25,33,-95,114,1,-118,82,-73,5,-84,-25,94,47,-121,104,11,82,-53,-111,-13,51,109,-125,-45,-66,-93,-77,-62,68,-69,-4,-73,92,101,-11,-56,-124,80,-70,68,-88,-45,-3,-2,-115,76,34,-15,110,-79,103,-33,-41,96,-100,7,24,-97,-24,94,59,74,33,-61,42,87,11,116,36,-90,-75,-50,-75,-97,-74,-79,96,37,-60,-63,38,1,-76,11,12,-127,28,-52,-89,49,44,-19,-101,-113,-85,-67,0,16,82,125,104,-109,-110,61,-93,-37,-38,72,-115,19,-31,55,13,5,73,-45,-43,7,56,95,21,-90,13,-43,-78,26,77,-18,-113,59,-127,-45,36,33,-47,127,72,126,61,100,29,-86,-31,87,-69,85,107,95,-108,44,-90,-127,-56,-86,13,68,113,-41,29,-120,80,109,-86,62,33,-10,50,-99,24,-123,38,122,-104,9,87,-94,107,12,27,-50,92,96,-1,-104,12,-21,112,83,-29,-70,48,-21,83,44,-21,-38,-98,38,-103,78,-63,49,-64,-32,106,-46,59,16,-11,-59,85,49,89,-83,-49,69,92,47,109,122,-121,-40,-21,-18,-72,118,-86,106,27,21,127,-119,-54,46,-65,59,100,78,-41,-71,-67,73,9,78,78,-124,-112,43,54,51,8,-113,14,-84,-22,-8,2,121,-122,-22,22,105,80,-116,-81,-53,-73,1,-101,-71,-93,-38,-125,-58,-110,-13,123,79,1,94,-85,77,-103,57,-12,88,50,-18,127,15,18,100,52,118,-29,99,-114,-124,109,11,-95,-16,-114,126,30,-94,-49,11,21,-41,-16,-20,106,-46,120,-128,-125,104,-116,121,56,-39,-108,-128,34,127,-82,-112,-127,-62,-84,114,-64,24,-30,-11,73,44,-116,-121,-89,-57,93,10,-123,-32,-16,71,-24,18,-58,0,43,26,120,-17,-62,30,-44,41,-124,-26,105,-89,13,-15,-31,68,0,8,-8,-29,30,124,-28,86,15,-77,66,-120,-14,53,17,-63,46,40,31,16,-119,43,-107,20,87,108,-1,112,-101,-41,41,52,-49,66,11,55,7,-14,125,-35,66,61,116,36,-100,-110,15,32,68,122,107,60,-120,-47,112,-8,-52,120,127,23,43,81,-106,-10,-111,91,-25,112,36,92,-36,42,46,-6,66,92,-91,54,-13,-79,55,-116,-127,-122,-54,-13,-80,49,-90,112,1,-98,-61,55,-71,-55,-19,43,-73,-15,113,97,40,37,-37,-44,-27,126,80,27,82,68,-123,108,-8,114,8,-72,118,-122,21,-34,-32,83,-95,98,14,-36,45,-36,26,98,7,35,-47,-15,3,41,-98,-104,39,-27,-49,-2,105,17,79,-45,116,-92,-126,-10,88,11,-41,7,-111,-128,-122,-112,82,90,52,23,81,17,-127,-56,-15,99,-23,110,-55,-117,75,43,122,66,-94,8,-32,-128,51,-50,-107,55,85,-88,116,36,-119,71,93,-24,-38,8,-102,-68,43,78,78,-120,-119,7,-104,113,-106,-110,94,-51,-24,-7,-111,48,-59,115,-100,82,90,-32,100,-112,112,66,19,122,25,118,-73,-78,114,104,-79,75,-121,50,-127,66,119,73,-101,23,50,45,77,13,-35,-113,24,118,5,-64,-85,57,-34,70,78,77,-101,-27,17,4,-42,34,-94,23,-103,-95,-44,100,65,107,67,-30,-18,37,100,53,126,106,74,-11,-61,-1,-111,-106,-125,-91,83,-121,-124,-23,90,-90,37,116,-108,65,-101,57,-5,57,69,-21,-10,63,19,12,-2,52,-21,-128,90,103,83,47,20,96,121,-92,46,119,58,118,41,58,-42,39,13,66,117,-13,-97,-18,-94,121,47,1,82,0,-29,88,21,-76,-114,16,-26,80,-91,-11,122,23,-76,-59,53,-2,6,116,8,-25,115,-32,-76,37,68,-89,-52,-28,-84,47,35,122,-6,-44,-112,90,-53,55,-113,84,127,72,109,-98,50,15,-63,-43,1,-42,-123,-87,42,-88,-57,49,56,-128,102,-89,69,-120,54,39,104,-9,92,98,102,112,-14,-33,-4,-93,37,2,50,-58,0,100,63,76,-103,76,13,66,-43,75,-75,-49,-58,70,37,-116,73,-40,88,28,-42,-38,89,116,-3,-74,-50,-88,80,-9,-36,10,40,87,107,-49,61,15,87,-115,57,75,-102,-33,59,107,15,42,56,-25,20,-128,-74,108,-24,-117,59,-111,56,-35,-95,26,69,-77,107,-43,23,-23,-29,7,26,-36,17,-20,-86,-51,72,-103,122,31,-38,70,107,-125,69,115,14,-46,-72,41,3,-88,-4,-115,26,-33,127,-116,-101,-98,28,-20,-111,111,69,14,-86,-120,-1,57,-65,-57,-15,-23,-2,111,87,-61,-30,-127,91,10,-27,-73,47,-53,-39,9,-18,-15,-93,-17,9,87,-51,-39,18,108,72,64,63,16,-108,-41,-110,27,-107,39,41,98,-62,-76,-79,-98,10,109,-82,-1,23,45,56,-46,98,4,-85,-111,25,110,-22,77,57,97,64,28,-119,93,110,-41,-50,-12,-114,-57,-15,76,30,94,-32,-82,13,49,38,-32,-43,-10,59,-127,-28,81,-16,33,114,-74,95,-96,-25,-64,62,-30,-17,69,43,-10,-106,79,89,-28,54,-52,99,40,85,-118,-105,62,13,67,117,68,-2,53,-73,-53,-14,51,-61,-89,75,-3,-59,-122,-49,51,-47,-34,-29,-17,-22,114,-69,120,27,-23,20,-104,-31,-51,-21,-63,96,120,-123,-7,22,50,-94,-62,-59,-73,-55,4,47,-90,15,-67,-68,-98,54,-98,-6,78,3,59,70,-72,-29,-3,-91,114,-64,49,-108,-56,-90,-41,127,27,55,28,-52,-84,-120,-88,-45,16,-2,3,-13,-100,56,24,33,90,54,-76,24,-31,2,0,119,69,-19,-49,-96,71,81,14,-60,49,-51,91,-105,-81,22,-114,57,95,-89,69,-117,41,-22,91,38,47,16,-121,105,-22,-106,97,50,-122,-73,-83,106,-89,-72,-45,80,43,-37,-95,16,73,104,-48,117,-115,-66,108,-64,-46,84,-102,-87,-62,27,57,-80,-34,-12,40,63,126,-1,-105,-33,-70,-16,7,-51,126,115,-113,120,-78,126,105,81,-83,14,97,-89,-36,-107,104,-93,-2,-106,-21,2,19,31,59,31,-45,-59,51,98,90,-25,-117,84,-20,32,-31,22,44,-115,94,-68,-14,12,-26,90,115,22,107,-83,-59,-62,100,74,-19,-52,-88,-18,-122,-120,-60,-69,-12,39,-77,-15,-89,-114,-126,-83,72,-50,24,-104,50,127,100,-104,37,43,-93,-111,-105,119,-118,-111,-118,109,-33,-88,112,-22,-3,52,-2,28,-101,81,-50,-18,8,-34,-41,-32,70,-91,51,119,-54,21,-59,-49,-78,59,27,67,99,-52,-17,53,-109,-111,-29,25,98,22,-55,19,25,5,-36,52,21,31,47,-40,1,-1,107,-74,-40,-61,35,-42,-113,-127,-46,-75,-13,-106,37,69,48,21,-29,54,-103,89,44,61,63,58,35,-19,98,-36,39,90,-21,82,43,-65,42,-74,-16,62,82,76,27,-79,73,-42,-104,41,56,77,69,-116,-81,-51,-101,-97,59,-93,86,54,-109,34,60,-35,15,-107,120,106,-48,-35,46,6,-74,-50,124,-7,62,-79,61,29,58,-47,98,118,7,127,-128,103,106,63,-111,71,-128,124,-124,16,15,21,2,91,-86,117,76,37,-62,114,-45,-73,-115,-35,-25,-39,-7,89,66,-47,-121,6,10,-65,-50,-118,42,9,-66,44,-106,-109,86,-97,-86,64,-13,-7,42,-15,-22,38,59,-99,-108,-104,-97,70,-19,-123,-114,41,-111,43,97,83,-95,30,-83,83,-117,-9,47,87,-46,-32,64,54,65,-35,-98,83,-58,14,-47,13,73,46,-41,3,-43,124,-7,-42,-16,-10,-119,116,-89,-127,-88,30,-11,-49,95,67,-100,53,-67,-61,-50,-62,51,36,96,44,-83,-33,59,-35,72};
    int random_block_sizes[NUMBER_OF_TESTS] = {397,93,468,336,187,528,449,496,481,455,528,32,150,419,148,21,195,301,467,201,401,93,428,54,451,480,274,514,439,86,536,193,94,440,374,238,266,82,232,386,430,282,393,355,9,550,152,356,285,303,318,450,582,600,365,507,60,228,24,218,117,205,5,3,263,344,416,430,468,538,440,467,175,592,447,536,294,500,312,387,32,64,540,459,483,353,153,426,217,118,107,511,56,366,232,264,33,454,565,48,182,235,240,84,527,463,340,353,94,14,107,71,537,165,579,459,412,205,537,173,374,321,101,419,537,538,430,393,298,461,275,590,64,167,299,434,515,123,154,130,561,369,195,384,29,399,100,301,168,111,417,568,157,249,19,229,100,91,311,134,423,496,342,449,150,123,593,319,62,468,83,366,253,282,302,250,276,539,365,574,22,219,256,477,130,5,564,206,473,396,461,116,75,514,338,267,109,103,536,578,39,420,371,264,72,413,202,572,236,595,475,434,34,356,588,277,256,510,146,579,417,102,105,402,81,42,301,31,378,569,158,551,296,384,327,371,198,333,150,338,212,584,584,332,53,62,383,83,60,30,96,529,565,530,17,447,64,97,382,316,425,503,584,365,64,224,271,21,339,98,173,444,478,57,158,457,442,485,330,310,586,584,573,44,569,330,445,522,315,429,182,452,4,570,528,57,598,424,317,503,544,73,500,501,216,70,21,138,330,226,255,515,43,436,215,307,238,102,338,88,360,452,322,434,486,56,481,422,257,78,97,130,154,169,594,576,473,198,525,503,172,476,559,185,434,18,570,168,77,40,469,297,463,584,136,296,201,266,477,122,12,406,212,379,418,476,201,174,8,183,199,252,252,557,484,135,578,108,29,566,460,327,273,497,403,155,592,455,66,434,96,524,102,221,149,537,599,427,220,229,543,361,99,318,293,446,91,128,201,237,149,366,212,187,279,291,468,324,457,22,233,91,141,411,541,261,548,100,261,110,17,319,131,312,32,583,365,106,323,428,447,566,457,347,191,113,554,359,112,280,246,265,298,141,436,510,413,412,233,489,330,183,477,134,590,79,274,149,389,306,314,11,377,230,232,242,79,508,251,234,405,107,157,144,211,65,293,450,79,148,330,93,75,494,368,533,513,101,443,375,154,131,434,76,490,301,7,537,48,382,70,447,584,218,310,380,517,140,83,294,437,477,402,55,60,295,522,359,304,47,52,581,419,480,175,135,99,551,103,383,45,450,343,67,382,424,447,277,454,154,366,469,549,445,372,438,104,133,274,409,184,87,203,530,28,80,437,72,235,238,459,257,71,255,202,110,445,146,422,119,347,225,60,312,448,439,408,227,600,214,383,146,452,185,204,30,21,412,183,453,562,377,588,499,15,530,211,56,508,187,276,497,338,525,266,79,67,141,60,490,162,83,314,583,326,165,225,460,403,445,389,149,34,60,75,533,362,520,463,428,1,169,9,116,595,6,410,537,362,181,414,594,344,463,3,255,221,87,362,448,34,159,449,507,426,254,91,396,159,455,587,585,7,287,350,371,227,49,493,251,591,543,507,75,438,421,538,475,336,439,16,233,349,331,418,444,55,507,439,9,120,288,495,41,157,95,372,68,568,71,281,267,509,205,578,460,365,534,315,22,178,283,26,269,122,517,422,444,92,142,304,167,448,521,19,424,88,474,254,294,346,500,27,321,416,168,12,410,588,104,409,414,436,205,156,260,300,43,517,393,64,179,60,104,311,188,147,97,260,324,174,531,425,556,468,210,255,327,98,534,572,180,324,176,380,191,2,426,71,119,375,242,568,256,155,89,151,574,508,556,533,91,98,58,577,421,364,144,569,392,442,32,127,462,133,466,258,155,266,33,14,361,398,322,408,472,553,477,78,290,349,310,250,206,434,571,189,434,309,325,41,232,240,356,43,348,241,101,189,162,293,2,574,457,439,339,317,153,186,329,380,566,425,154,445,19,310,341,593,528,279,398,547,380,171,16,216,56,429,342,406,188,334,132,508,548,55,333,141,43,451,235,19,341,457,522,235,86,20,309,598,364,220,552,535,424,483,125,510,376,445,578,308,269,8,386,37,14,361,547,38,486,502,559,139,180,85,502,437,132,342,284,101,59,495,407,3,539,545,164,280,504,539,255,65,319,396,579,594,191,208,462,116,567,222,406,142,318,29,397,526,90,42,165,286,165,363,17,243,412,443,42,588,333,4,461,179,494,279,457,263,546,99,281,246,510,189,297,284,203,95,344,268,143,176,336,362,524,220,483,127,269,415,557,552,264,462,439,371,432,134,366,132,89,498,430,250,198,352,358,270,531,72,464,86,541,546,19,454,403,498,521,349,359,270,248,107,403,575,444,392,109,62,222,476,213,516,598,152,152,109,466,17,9,438,395,482,560,275,195,231,109,404,45,266,4,469,304,91,142,262,384,37,573,140,134,362,340,160,232,94,309,83,275,368,499,420,554,360,7,240,195,549,557,290,546,507,259,354,166,361,246,297,428,118,4,584,8,241,523,329,102,342,545,446,58,280,173,410,212,242,79,575,75,486,529,8,417,495,219,235,245,103,295,324,511,205,459,167,289,548,43,386,399,20,425,559,37,226,379,211,107,301,394,592,65,274,243,394,274,281,492,12,550,507,73,515,522,399,334,278,416,510,184,558,148,331,285,111,410,204,273,563,164,116,146,497,488,189,89,531,319,413,214,78,30,442,416,353,469,317,267,496,584,222,291,514,6,405,430,151,563,415,44,358,108,321,583,206,276,319,448,595,76,324,230,523,74,309,425,304,69,591,61,489,482,157,459,387,558,559,574,326,352,300,258,456,227,49,360,173,363,203,471,257,238,383,359,263,560,413,146,557,146,215,177,88,318,555,465,70,495,28,45,204,531,284,424,506,505,127,243,145,501,569,303,151,541,417,412,577,193,428,364,349,109,447,283,264,3,591,368,499,350,359,233,91,318,8,148,463,478,143,52,258,555,503,380,438,301,410,533,105,463,75,176,593,514,135,39,444,115,239,432,563,579,515,2,78,61,305,593,487,112,424,52,12,149,469,517,303,589,522,530,459,224,157,69,503,283,532,425,114,308,89,202,578,7,206,320,429,523,355,297,412,574,68,499,445,223,207,537,22,152,93,57,414,532,256,407,329,59,40,56,46,508,34,353,480,28,490,563,289,386,249,445,529,414,334,292,583,456,372,561,195,101,549,493,16,187,579,536,386,316,585,463,588,165,537,31,574,111,262,26,460,390,308,285,428,199,508,497,547,483,345,175,308,19,339,524,422,561,193,144,493,226,113,44,354,149,512,370,364,464,509,173,148,524,110,293,103,462,441,475,503,203,158,213,390,33,335,546,477,191,331,171,403,125,392,69,263,352,539,445,520,361,79,543,308,481,142,75,14,69,358,305,594,21,35,58,133,550,437,333,514,387,317,99,251,453,462,270,241,357,46,551,412,197,320,238,7,599,280,78,324,196,550,581,472,145,249,318,539,555,429,81,185,309,482,279,385,205,34,59,208,107,512,74,93,512,539,157,60,493,225,35,187,564,513,467,314,14,452,331,578,211,409,281,378,299,290,284,580,29,484,170,340,116,297,572,434,4,20,357,537,262,96,192,254,340,579,106,370,20,499,512,163,181,279,272,196,536,303,468,543,595,64,214,55,577,384,193,163,235,429,215,151,3,113,288,410,597,94,248,3,172,85,322,590,61,396,255,386,408,436,11,203,119,10,327,160,515,554,74,428,198,259,483,585,578,73,55,293,591,195,98,49,186,451,43,285,145,594,531,14,511,291,7,521,70,264,454,4,526,284,375,476,201,196,79,284,46,247,46,343,312,36,14,432,566,361,333,50,329,577,255,585,420,386,198,99,132,132,489,470,336,34,299,362,303,496,103,91,374,191,72,62,108,275,446,114,582,81,459,478,529,437,86,207,349,303,127,544,556,299,157,445,335,415,526,140,426,158,3,108,369,574,178,431,214,306,130,385,241,467,91,246,61,600,600,100,282,321,105,580,581,425,544,444,537,541,15,125,410,537,310,597,346,363,124,154,127,566,550,71,584,481,190,419,557,550,400,93,491,390,389,83,397,271,453,112,224,446,588,50,492,266,396,537,151,182,330,371,178,227,507,338,414,418,530,204,512,449,193,308,32,404,374,362,539,547,128,486,119,324,207,287,66,125,430,456,355,416,202,592,180,415,2,579,65,327,162,432,248,230,494,509,478,443,281,68,340,195,409,228,232,125,556,105,129,312,326,448,111,132,112,168,139,285,367,382,14,24,195,521,194,437,511,213,283,7,50,116,582,497,82,478,172,85,570,345,130,259,6,423,586,87,174,303,391,46,596,277,592,26,130,348,55,204,431,597,221,176,97,479,290,129,322,102,137,173,96,98,56,259,594,430,31,58,100,396,161,282,121,473,577,85,556,584,528,471,409,531,193,515,304,587,487,407,170,289,529,462,557,552,513,317,129,178,3,302,538,33,205,313,157,36,81,216,60,71,26,343,430,50,449,7,339,201,142,387,557,120,336,445,575,518,126,221,357,355,115,216,535,158,169,462,188,128,30,356,536,589,473,134,34,310,228,100,568,443,183,503,107,579,109,566,67,518,121,7,503,323,240,120,537,84,37,141,545,269,593,349,317,168,417,455,99,499,343,469,84,211,73,88,111,425,595,287,507,366,174,208,284,123,276,89,502,341,173,10,309,341,268,430,327,541,599,180,260,337,184,265,455,56,471,46,285,363,201,53,100,418,572,588,104,35,560,584,152,455,337,212,422,377,359,282,161,432,283,150,94,331,159,237,415,245,518,256,365,123,428,314,348,485,295,316,550,187,237,377,101,193,576,29,55,165,174,391,165,220,399,433,419,134,379,46,485,128,32,106,50,83,582,592,95,383,306,58,593,57,592,482,77,183,556,532,114,208,519,110,162,315,243,145,276,508,88,82,530,430,105,546,40,302,30,215,248,279,96,55,397,8,78,184,359,532,392,196,346,189,226,337,297,120,465,378,300,218,297,47,478,356,351,169,498,35,555,396,545,48,557,256,44,585,478,310,79,303,470,510,459,114,1,526,379,278,444,530,412,259,228,43,163,339,264,236,400,36,21,51,255,116,534,129,432,188,567,45,2,234,76,129,162,577,183,146,38,79,447,173,519,49,457,417,525,407,367,100,404,480,428,163,460,516,209,387,388,587,511,168,349,506,230,568,247,462,319,499,477,120,95,100,256,123,583,13,421,285,571,41,522,565,33,326,67,123,545,396,224,151,54,274,300,446,188,81,373,334,598,219,273,118,102,575,69,90,440,206,3,375,45,33,206,198,14,550,475,460,94,164,518,180,449,498,397,263,412,221,241,383,234,135,198,15,54,584,428,168,144,486,305,532,38,11,495,316,429,447,429,428,254,385,103,596,502,433,134,452,495,207,289,58,435,206,140,596,145,348,19,370,475,507,439,137,470,347,451,19,37,443,130,224,444,346,525,425,78,307,524,292,279,460,83,597,208,14,134,310,342,519,58,510,137,280,101,170,192,595,534,425,325,246,557,199,359,477,117,119,522,322,569,349,255,170,226,102,350,169,363,94,465,552,240,129,161,356,556,189,24,293,315,498,305,66,218,127,29,451,481,186,557,395,256,52,141,420,425,146,507,103,58,428,61,125,36,556,56,147,406,539,501,555,360,33,217,208,295,309,318,411,458,590,470,28,173,513,321,227,12,248,499,467,596,576,337,336,145,4,199,544,444,300,418,323,118,209,21,460,305,13,411,27,239,133,353,87,155,385,562,85,499,451,537,531,28,282,288,181,224,474,362,264,143,486,239,501,311,81,295,162,108,85,61,72,145,579,397,446,440,367,588,295,264,68,229,553,518,108,151,554,289,415,418,261,121,453,344,266,582,26,374,47,63,356,273,522,480,456,205,252,237,362,555,394,516,76,40,108,513,52,444,497,11,342,477,203,482,12,535,319,599,246,503,585,138,18,85,180,87,568,36,562,549,527,63,249,207,486,286,410,132,506,45,306,378,41,305,546,187,141,176,352,111,179,349,356,281,470,16,37,579,161,544,481,122,330,267,513,224,553,279,151,137,395,44,6,582,456,180,197,498,208,272,375,339,427,567,204,31,16,274,169,238,169,97,346,38,372,160,280,581,132,99,521,88,415,27,66,338,288,332,293,65,474,552,445,256,1,179,481,595,50,290,482,151,535,430,164,16,374,505,85,134,566,159,37,27,543,79,174,544,41,193,536,442,248,472,237,281,410,115,166,323,214,82,470,189,385,598,5,320,416,202,43,529,250,49,291,507,236,83,496,282,388,214,290,185,424,515,349,256,387,408,283,76,174,144,582,551,524,152,334,252,587,300,104,112,340,326,238,427,90,83,509,89,508,492,353,471,22,257,535,234,450,436,358,487,481,322,523,271,526,23,375,474,71,137,548,340,127,25,13,291,297,552,274,437,598,488,61,150,25,367,163,183,247,565,62,206,281,251,201,554,426,133,454,414,570,298,270,424,59,37,183,482,154,598,363,186,433,564,46,513,480,96,138,377,410,349,270,389,578,255,397,441,530,514,396,510,471,145,223,507,75,207,251,364,589,462,435,4,600,265,280,254,35,286,218,95,366,161,419,426,328,112,509,297,257,368,468,261,389,555,219,286,432,486,263,554,460,230,210,66,290,585,74,269,359,70,475,588,208,117,341,306,304,12,119,85,364,318,288,341,252,438,104,409,400,306,69,187,170,46,154,204,327,434,17,294,336,536,514,306,110,300,79,399,528,12,81,225,277,555,130,344,468,444,55,247,380,547,439,136,551,386,322,314,101,301,435,202,529,408,151,88,77,321,140,267,108,111,347,318,553,21,98,250,5,354,108,69,404,58,316,562,385,534,492,117,395,319,365,292,62,98,130,411,2,489,384,105,564,426,441,549,277,338,550,529,319,499,424,192,288,320,458,176,265,45,525,150,224,196,96,296,533,588,45,437,321,288,303,280,385,362,129,548,260,220,38,453,586,397,244,600,174,196,469,400,398,88,269,215,329,283,596,102,205,340,489,308,124,243,363,235,38,521,423,195,212,52,81,421,385,465,316,89,91,270,312,378,392,16,14,131,10,506,587,114,322,343,517,219,62,124,165,504,188,479,31,394,376,196,228,496,123,509,519,121,166,512,486,96,168,251,2,457,217,438,177,578,271,453,487,349,393,349,538,183,105,18,38,124,299,357,381,508,148,240,185,279,363,323,45,106,596,141,399,51,284,102,291,574,348,387,277,121,115,463,590,4,222,53,406,534,335,283,419,413,312,440,24,154,393,411,505,407,507,505,482,384,114,443,395,93,253,254,498,551,4,159,568,221,281,571,167,242,372,360,494,557,138,200,58,315,336,448,272,183,80,151,104,162,109,122,463,84,472,202,471,346,452,252,494,244,78,140,51,414,332,387,546,193,320,235,553,55,284,465,452,299,545,401,220,243,537,84,103,101,144,505,478,563,521,503,581,536,148,372,553,424,392,376,449,248,227,273,270,204,507,231,228,455,291,584,423,199,325,515,241,96,459,297,314,128,437,479,351,55,132,57,414,254,424,281,58,217,537,274,586,70,224,398,211,100,502,267,359,124,162,199,217,461,148,556,431,16,321,60,109,579,383,139,263,4,123,297,196,28,441,289,278,411,158,266,367,588,473,76,541,311,54,363,390,395,385,151,471,340,376,65,393,199,463,577,343,108,136,132,86,116,506,522,556,13,569,537,144,21,487,395,204,161,410,352,246,492,285,184,241,93,91,546,365,335,89,598,341,516,313,16,67,466,68,218,405,181,593,97,533,280,545,183,181,257,373,17,396,162,81,122,251,521,268,359,475,406,12,18,396,87,583,102,217,60,405,364,271,487,118,543,350,193,168,150,8,189,580,118,428,513,268,183,131,213,491,555,459,381,40,156,1,537,510,190,533,124,13,32,357,292,575,46,107,597,569,597,436,312,597,221,592,145,55,415,581,83,9,139,366,574,510,363,475,384,308,203,417,97,591,515,387,324,468,420,371,521,215,310,329,105,418,207,168,185,504,392,29,75,243,326,358,69,530,170,19,386,346,537,349,68,120,270,54,159,77,566,74,365,339,233,360,495,206,219,52,562,579,555,82,62,211,185,233,189,65,387,560,149,398,566,436,361,424,597,329,546,129,64,223,329,317,272,516,513,536,546,517,175,489,469,426,454,467,269,396,215,59,439,472,79,95,486,22,171,132,494,388,541,12,219,424,176,290,37,274,68,427,278,468,272,384,344,284,438,14,498,6,32,514,591,150,142,273,450,493,279,48,290,390,580,514,392,520,247,591,433,27,426,162,536,414,478,481,267,533,417,556,58,330,175,470,325,331,470,533,285,283,163,481,490,482,257,234,199,24,30,185,356,348,282,507,93,251,17,471,206,555,191,257,482,78,595,410,524,352,488,445,223,355,172,52,445,510,430,44,224,81,585,8,193,353,515,127,417,510,166,56,378,581,308,486,159,230,581,266,390,489,299,107,192,79,60,269,212,337,32,118,522,289,424,402,242,396,395,133,326,202,386,538,86,301,198,211,527,73,101,395,34,596,310,306,392,40,144,190,269,505,326,571,435,261,277,421,409,338,568,120,489,2,315,131,97,509,168,588,39,354,220,446,182,230,521,559,430,249,51,209,566,448,547,333,346,442,46,562,281,561,401,98,291,27,24,102,589,69,289,157,517,190,243,495,368,404,552,524,20,55,200,541,466,267,28,40,550,210,361,290,529,387,373,273,419,88,31,563,8,483,98,330,130,50,418,176,273,153,586,299,111,335,471,49,561,9,475,473,592,30,386,34,326,448,68,535,148,333,427,331,403,308,36,27,427,584,184,579,193,368,593,589,415,90,421,46,595,118,202,279,190,323,268,71,533,473,283,360,61,200,20,350,86,98,314,569,288,221,559,350,242,533,480,479,103,45,164,178,297,130,188,211,236,164,589,384,127,486,427,62,589,264,119,443,304,244,64,137,400,325,22,125,309,276,226,254,587,512,62,70,385};

    size_t total_bytes = 0;
    int total_blocks = 0;
    char reference_arr_bytes_blocks[NUMBER_OF_TESTS][MAX_BLOCK_SIZE] = {0}; // without malloc
    int reference_arr_block_sizes[NUMBER_OF_TESTS] = {0};
    char* bytes_blocks[NUMBER_OF_TESTS];
    assert(_num_allocated_bytes()==0);
    assert(_num_allocated_blocks() == 0);
    for (int i = 0; i < NUMBER_OF_TESTS; i++) {
        int number_of_bytes_in_new_block = random_block_sizes[i];
        reference_arr_block_sizes[i] = number_of_bytes_in_new_block; // how many bytes are in the block i
        bytes_blocks[i] = (char*)malloc((size_t)number_of_bytes_in_new_block);
        for (int j = 0; j < number_of_bytes_in_new_block; j++) {
            char new_byte = random_bytes[j];
            reference_arr_bytes_blocks[i][j] = new_byte;
            bytes_blocks[i][j] = new_byte;
            assert(bytes_blocks[i] + j <= number_of_bytes_in_new_block + bytes_blocks[i]);
        }

    }
    //assert(total_blocks == _num_allocated_blocks());
    //assert(total_bytes == _num_allocated_bytes());
    // Now we have a reference array without malloc, and bytes_blocks with malloc. lets compare them
    for (int i = 0; i < NUMBER_OF_TESTS; i++) {
        for (int j = 0; j < reference_arr_block_sizes[i]; j++) { // That's why we kept the sizes :)
            assert(bytes_blocks[i][j] == reference_arr_bytes_blocks[i][j]);
        }
    }
    //assert(_num_free_blocks() == 0);
    int test_blocks_to_free[NUM_OF_BLOCKS_TO_FREE] = {1677,1775,1656,1376,986,2086,2851,1287,332,863,886,773,526,2838,2668,326,1954,2414,1409,2736,1655,1731,2550,1173,399,2813,1379,2205,1868,1502,1185,388,1457,456,689,185,2438,1880,6,1231,845,2023,1203,654,77,675,1307,1956,429,546,778,2798,1764,49,2810,85,779,2930,840,2008,2217,2304,1327,797,2658,1835,1431,1625,524,1639,2936,466,2289,1206,785,835,2560,1474,255,658,2757,387,569,786,2094,2347,1807,1518,1361,101,285,2664,377,374,250,2802,652,781,360,2612,1384,108,2123,1699,2018,267,709,1798,1536,153,1235,936,854,2875,2710,2565,2342,1785,1786,2029,1978,650,188,2969,1803,1158,857,41,2346,2231,536,457,2447,1607,2028,2119,2024,669,2541,1389,1483,2835,551,1723,2032,315,345,1346,1510,892,1095,234,1011,2340,1909,2370,1065,1833,514,2260,2390,2632,1427,1550,2824,1462,393,711,799,2378,460,2622,2495,1657,417,2429,765,2374,114,1128,930,873,1642,846,170,2424,80,2041,2873,2454,2855,1919,1622,2382,1767,577,1041,843,2767,1029,655,632,2406,2694,1687,451,940,1984,1459,2136,98,2656,1297,2759,565,2326,2436,1304,2014,994,1179,1543,1171,1343,2641,714,580,1515,1718,1911,1335,2898,1969,1377,2984,1364,887,288,2891,2536,590,2183,12,385,753,2754,2240,674,872,1135,983,864,1873,2511,1665,2500,2435,902,2204,1898,1371,665,564,2423,1781,492,2744,125,500,630,376,467,338,323,340,1196,603,1197,1794,2102,1049,2288,554,349,947,173,2921,2811,200,2866,501,2899,1357,1830,2559,1422,1412,1493,2636,1217,507,545,2571,358,1019,2369,182,2968,2104,2992,123,1991,2026,2282,419,21,2761,1176,1057,2760,2479,927,1480,2432,1339,300,2995,150,2243,1706,2990,2852,1280,1841,1337,1076,763,2523,28,2097,1529,2206,2497,261,1905,61,2882,244,2251,2703,1045,578,1636,1478,981,1761,214,2317,2031,266,1279,1043,1801,732,624,715,505,1779,243,391,222,2914,2330,512,1090,995,616,2252,2706,912,1586,1799,1295,34,720,776,860,1071,2318,2976,1872,1690,620,494,1443,2258,1826,2861,445,2788,2177,2581,562,2107,1147,2674,2518,838,592,53,223,1897,1265,2284,134,2867,1561,2473,1260,1040,999,841,2060,1475,2529,2553,24,2853,1611,1026,1891,535,2379,58,2854,746,128,1533,249,1817,247,2957,960,1424,62,79,818,111,265,252,975,72,2048,263,1150,1030,1604,1693,2804,1223,1569,1385,2903,2527,595,2666,2895,1003,334,1931,1332,755,1149,696,2911,2960,1416,2654,314,1294,40,2306,861,2837,319,2643,1112,1917,1031,362,2187,1105,473,1333,2195,1668,2458,1595,171,1025,1262,1704,1383,324,920,2283,1941,933,491,2393,1620,1329,1884,2189,2411,293,2847,1584,1055,1979,690,980,1526,962,1331,638,847,1489,2482,2208,1505,441,2542,1740,608,2607,1229,2138,1986,1610,2948,1372,2827,1992,621,1660,568,1857,2118,1317,2499,2161,1544,2343,1319,1314,2932,968,2159,1651,2087,2403,404,463,1283,2709,2475,1968,889,1612,1226,2307,2624,2013,260,2955,2585,1078,2786,413,2105,23,2951,2772,853,1838,566,728,2535,2033,1320,1939,1242,2037,270,1688,888,2768,2876,2923,1774,2244,2311,2433,477,774,208,1044,2889,2352,2849,934,438,691,2234,259,2834,2557,1990,2712,1054,1967,1027,928,694,2077,1441,1000,1924,869,2576,425,803,2702,2985,2157,369,2975,2472,750,2534,1987,1966,2073,1634,189,2510,1227,2229,17,428,306,511,2815,1244,1580,1419,529,2595,2883,2714,16,2543,942,2294,1667,2109,777,2168,613,2871,563,1751,1792,575,2645,2140,281,2925,2514,534,2186,1449,2949,820,1312,204,1773,583,822,2196,389,2540,2554,1910,1528,1445,1200,148,2965,1363,2322,948,2547,1591,751,890,2362,2730,984,2444,766,242,2688,1046,2160,2904,1394,508,2825,56,648,383,1291,2659,316,931,2698,1401,240,88,2613,2725,2248,2799,2047,31,2030,1780,2657,2211,1198,2650,880,913,1675,1879,219,426,195,2787,587,1608,2448,729,553,1855,1590,611,1864,2791,2586,2765,2743,1724,2103,1311,211,1659,1366,919,788,2667,793,2537,978,2890,2707,625,1155,2222,2398,698,2027,2498,292,916,1523,2314,2517,1628,55,1683,1976,1344,1465,1846,2091,814,725,830,1368,789,51,138,1609,406,18,1005,1310,1508,2238,2441,68,2610,593,510,202,894,1627,2350,2532,2409,1133,2777,2286,1768,2463,268,1263,168,2683,607,2770,518,2139,401,499,1726,1737,736,1556,151,2443,2427,436,1362,1658,1736,2455,131,274,2900,2621,1729,446,1254,2701,2753,1270,1629,176,205,817,1542,2166,203,2663,1248,433,1845,1157,2000,2938,1587,2814,2377,2236,1160,1153,540,602,206,1330,2328,988,1438,2583,370,742,748,1437,1380,225,2355,2728,1606,2151,2466,2530,2909,279,2917,282,1771,2483,2450,769,2566,1856,1286,1213,1487,2163,2046,2954,341,2230,946,2826,2628,1820,461,1036,1597,1066,418,2893,1605,375,83,646,749,1253,1900,480,1617,2192,1012,1784,105,1067,2359,1435,2061,1797,2672,228,152,308,1110,2210,1458,1024,2539,2913,449,1237,1093,795,2456,1680,557,1060,483,2431,262,1017,915,246,2430,488,472,447,273,700,2935,1995,2009,600,541,2896,1467,287,2795,1367,1082,468,2474,2323,331,133,272,66,2043,1354,69,2829,1867,570};
    for (int i = 0; i < NUM_OF_BLOCKS_TO_FREE; i++) {
        free(bytes_blocks[test_blocks_to_free[i]]);
    }
    assert(_num_free_blocks() > 0 && _num_free_blocks() <= NUM_OF_BLOCKS_TO_FREE);

    for (int i = 0; i < NUM_OF_BLOCKS_TO_FREE; i++) {
        int new_index = test_blocks_to_free[i];
        int number_of_bytes_in_new_block = random_block_sizes[new_index];

        reference_arr_block_sizes[new_index] = number_of_bytes_in_new_block; // how many bytes are in the block i
        bytes_blocks[new_index] = (char*)malloc((size_t)number_of_bytes_in_new_block);

        for (int j = 0; j < number_of_bytes_in_new_block; j++) {
            char new_byte = random_bytes[j];
            reference_arr_bytes_blocks[new_index][j] = new_byte;
            bytes_blocks[new_index][j] = new_byte;
        }
    }

    for (int i = 0; i < NUMBER_OF_TESTS; i++) {
        for (int j = 0; j < reference_arr_block_sizes[i]; j++) { // That's why we kept the sizes :)
            assert(bytes_blocks[i][j] == reference_arr_bytes_blocks[i][j]);
        }
    }

    for (int i = 0; i < NUM_OF_BLOCKS_TO_FREE; i++) {
        int new_index = i + 400;
        int number_of_bytes_in_new_block = random_block_sizes[new_index];

        reference_arr_block_sizes[new_index] = number_of_bytes_in_new_block; // how many bytes are in the block i
        bytes_blocks[new_index] = (char*)realloc(bytes_blocks[new_index], (size_t)
                number_of_bytes_in_new_block);

        for (int j = 0; j < number_of_bytes_in_new_block; j++) {
            char new_byte = random_bytes[j];
            reference_arr_bytes_blocks[new_index][j] = new_byte;
            bytes_blocks[new_index][j] = new_byte;
        }
    }
    for (int i = 0; i < NUMBER_OF_TESTS; i++) {
        for (int j = 0; j < reference_arr_block_sizes[i]; j++) { // That's why we kept the sizes :)
            assert(bytes_blocks[i][j] == reference_arr_bytes_blocks[i][j]);
        }
    }

}




int main() {
    global_list_init = NULL;
    malloc3_test_01();
    global_list_init = NULL;
    malloc3_test_02();
    global_list_init = NULL;
    malloc3_test_03();
    global_list_init = NULL;
    oran();
    global_list_init = NULL;
  //  remalloc_3_test();

    global_list_init = NULL;
    malloc3_test_011();
    global_list_init = NULL;
    malloc3_test_021();
    global_list_init = NULL;
    malloc3_test_031();
    global_list_init = NULL;
    malloc_bytes_comparison_stress_test();

    std::cout << "DONE" ;

    return 0;
}
