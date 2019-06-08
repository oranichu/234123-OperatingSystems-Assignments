#include <iostream>
#include <unistd.h>
#import <stdlib.h>

typedef struct Meta_Data_t {

    size_t m_init_allocation;
    size_t m_requested_allocation;
    bool m_is_free;
    Meta_Data_t *m_next;

} Meta_Data;

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

void *calloc(size_t size) {

    void *ptr = malloc(size);
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

size_t _num_free_blocks() {
    size_t counter = 0;
    if (global_list_init == NULL) {
        return 0;
    }
    global_list = global_list_init;
    while (global_list->m_next != NULL) {
        if (global_list->m_is_free) {
            counter++;
        }
        global_list = global_list->m_next;
    }

    if (global_list->m_is_free) {
        counter++;
    }
    return counter;
}

size_t _num_free_bytes() {
    size_t counter = 0;
    if (global_list_init == NULL) {
        return 0;
    }

    global_list = global_list_init;
    while (global_list->m_next != NULL) {
        if (global_list->m_is_free) {
            counter += global_list->m_init_allocation;
        }
        global_list = global_list->m_next;
    }

    if (global_list->m_is_free) {
        counter += global_list->m_init_allocation;
    }

    return counter;
}

size_t _num_allocated_blocks() {
    size_t counter = 0;
    if (global_list_init == NULL) {
        return 0;
    }

    global_list = global_list_init;
    while (global_list->m_next != NULL) {
        if (!global_list->m_is_free) {
            counter++;
        }
        global_list = global_list->m_next;
    }

    if (!global_list->m_is_free) {
        counter++;
    }

    return counter;
}


size_t _num_allocated_bytes() {
    size_t counter = 0;
    if (global_list_init == NULL) {
        return 0;
    }

    global_list = global_list_init;
    while (global_list->m_next != NULL) {
        if (!global_list->m_is_free) {
            counter += global_list->m_init_allocation;
        }
        global_list = global_list->m_next;
    }

    if (!global_list->m_is_free) {
        counter += global_list->m_init_allocation;
    }

    return counter;
}

size_t _num_meta_data_bytes() {
    return META_SIZE * (_num_allocated_blocks() + _num_free_blocks());
}

size_t _size_meta_data() {
    return META_SIZE;
}


int main() {
    assert(malloc(0) == NULL);
    assert(malloc(MAX_MALLOC_SIZE + 1) == NULL);

    void *omer;
    omer = malloc(100);
    assert(_num_allocated_blocks() == 1);
    assert(_num_free_blocks() == 0);
    assert(_num_allocated_bytes() == 100);
    assert(_num_meta_data_bytes() == META_SIZE);
    assert(_num_free_bytes() == 0);

    free(omer);
    assert(_num_allocated_blocks() == 0);
    assert(_num_free_blocks() == 1);
    omer = malloc(50);
    assert(_num_allocated_blocks() == 1);
    assert(_num_free_blocks() == 0);

    free(omer);
    assert(_num_allocated_blocks() == 0);
    assert(_num_free_blocks() == 1);
    omer = malloc(70);
    assert(_num_allocated_blocks() == 1);
    assert(_num_free_blocks() == 0);

    free(omer);
    assert(_num_allocated_blocks() == 0);
    assert(_num_free_blocks() == 1);
    omer = malloc(101);
    assert(_num_allocated_blocks() == 1);
    assert(_num_free_blocks() == 1);

    omer = malloc(70);
    assert(_num_allocated_blocks() == 2);
    assert(_num_free_blocks() == 0);

    void *omer2 = malloc(50);

    omer2 = malloc(70);
    omer = malloc(70);
    omer = malloc(70);

    assert(_num_allocated_blocks() == 6);
    assert(_num_free_blocks() == 0);

    free(omer2);
    assert(_num_allocated_blocks() == 5);
    assert(_num_free_blocks() == 1);

    omer2 = malloc(110);
    assert(_num_allocated_blocks() == 6);
    assert(_num_free_blocks() == 1);

    omer2 = malloc(69);
    assert(_num_allocated_blocks() == 7);
    assert(_num_free_blocks() == 0);

    char *omer3 = (char *) calloc(50);
    assert(_num_allocated_blocks() == 8);
    assert(_num_free_blocks() == 0);
    for (int i = 0; i < 50; ++i) {
        assert(omer3[i] == 0);
        omer3[i] = i;
    }

    char *omer4 = (char *) realloc(omer3, 100);
    assert(_num_allocated_blocks() == 8);
    assert(_num_free_blocks() == 1);
    for (int j = 0; j < 50; ++j) {
        assert(omer4[j] == j);
    }

    omer3 = (char*)malloc(30);
    assert(_num_allocated_blocks() == 9);
    assert(_num_free_blocks() == 0);
    omer4 = (char*)realloc(omer3, 40);
    assert(_num_allocated_blocks() == 9);
    assert(_num_free_blocks() == 0);

    return 0;
}