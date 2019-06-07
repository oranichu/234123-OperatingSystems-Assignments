#include <iostream>
#include <unistd.h>

#define MAX_MALLOC_SIZE 100000000
void* malloc(size_t size) {

    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return NULL;
    }
    intptr_t increment = size;
    void* prev_program_break = sbrk(increment);

    if (*(int*)prev_program_break < 0) {
        return NULL;
    }

    return prev_program_break;

}

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
