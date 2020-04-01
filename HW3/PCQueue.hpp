#ifndef _QUEUEL_H
#define _QUEUEL_H

#include "Headers.hpp"
#include "Semaphore.hpp"

// Single Producer - Multiple Consumer queue
template<typename T>
class PCQueue {

public:

    PCQueue();

    ~PCQueue();

    // Blocks while queue is empty. When queue holds items, allows for a single
    // thread to enter and remove an item from the front of the queue and return it.
    // Assumes multiple consumers.
    T pop();

    // Allows for producer to enter with *minimal delay* and push items to back of the queue.
    // Hint for *minimal delay* - Allow the consumers to delay the producer as little as possible.
    // Assumes single producer
    void push(const T &item);

private:
    // Add your class memebers here
    Semaphore           m_queueSize;
    pthread_mutexattr_t m_mutexAttr;
    pthread_mutex_t     m_mutexLock;
    queue<T>            m_queue;
    unsigned            m_uPushWaiting;
    pthread_cond_t      m_pushCond;

};

template<typename T>
PCQueue<T>::PCQueue(): m_uPushWaiting(0) {
    pthread_mutexattr_init(&m_mutexAttr);
    pthread_mutexattr_settype(&m_mutexAttr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&m_mutexLock, &m_mutexAttr);
    pthread_cond_init(&m_pushCond, nullptr);
    // m_queueSize and m_queue is constructed automatically
}

template<typename T>
PCQueue<T>::~PCQueue() {
    pthread_mutex_destroy(&m_mutexLock);
    pthread_mutexattr_destroy(&m_mutexAttr);
    pthread_cond_destroy(&m_pushCond);
}

template<typename T>
T PCQueue<T>::pop() {
    m_queueSize.down();
    pthread_mutex_lock(&m_mutexLock);
    while (m_uPushWaiting > 0) {
        pthread_cond_wait(&m_pushCond, &m_mutexLock);
    }
    T temp = m_queue.front();
    m_queue.pop();
    pthread_mutex_unlock(&m_mutexLock);
    return temp;
}

template<typename T>
void PCQueue<T>::push(const T &item) {
    m_uPushWaiting++;
    pthread_mutex_lock(&m_mutexLock);
    m_queueSize.up();
    m_queue.push(item);
    m_uPushWaiting--;
    pthread_cond_broadcast(&m_pushCond);
    pthread_mutex_unlock(&m_mutexLock);
}
// Recommendation: Use the implementation of the std::queue for this exercise
#endif