//
// Created by user on 23/05/2019.
//

#ifndef OS_WET3_REVSEMAPHORE_H
#define OS_WET3_REVSEMAPHORE_H

#include "Headers.hpp"

class RevSem {
public:

    RevSem() = default;

    ~RevSem();

    void initRevSem(uint val);

    void wait();

    void post();

private:
    uint m_uCounter;
    uint m_num_post_to_wait;
    pthread_mutexattr_t m_mutexAttr;
    pthread_mutex_t m_mutexLock;
    queue<pthread_cond_t *> m_postQueue;
    queue<pthread_cond_t *> m_waitQueue;
};

#endif



