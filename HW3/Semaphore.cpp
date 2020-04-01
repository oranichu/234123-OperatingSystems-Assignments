//
// Created by user on 13/05/2019.
//

#include "Semaphore.hpp"

Semaphore::Semaphore() : Semaphore(0) {}

Semaphore::Semaphore(unsigned val) : m_uCounter(val) {
    if (DEBUG) cout << "INIT counter=" << val << endl;
    pthread_mutexattr_init(&m_mutexAttr);
    pthread_mutexattr_settype(&m_mutexAttr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&m_mutexLock, &m_mutexAttr);
    // m_waitQueue is constructed automatically
}

Semaphore::~Semaphore() {
    if (DEBUG) cout << "DESTROY" << endl;
    while (!m_waitQueue.empty()) {
        pthread_cond_destroy(m_waitQueue.front());
        m_waitQueue.pop();
    }
    pthread_mutex_destroy(&m_mutexLock);
    pthread_mutexattr_destroy(&m_mutexAttr);
}

void Semaphore::up() {
    pthread_mutex_lock(&m_mutexLock);
    if (DEBUG) cout << pthread_self() << " up() mutex lock" << endl;
    if (!m_waitQueue.empty()) {
        if (DEBUG) cout << pthread_self() << " wake up a thread" << endl;
        pthread_cond_signal(m_waitQueue.front());
        m_waitQueue.pop();
    } else if (DEBUG) cout << pthread_self() << " no threads to wake up" << endl;
    m_uCounter++;
    if (DEBUG) cout << pthread_self() << " update counter=" << m_uCounter << endl;
    if (DEBUG) cout << pthread_self() << " up() mutex unlock" << endl;
    pthread_mutex_unlock(&m_mutexLock);
}


void Semaphore::down() {
    pthread_mutex_lock(&m_mutexLock);
    if (DEBUG) cout << pthread_self() << " down() mutex lock" << endl;
    while (m_uCounter == 0) {
        pthread_cond_t new_cond;
        pthread_cond_init(&new_cond, nullptr);
        m_waitQueue.push(&new_cond);
        if (DEBUG) cout << pthread_self() << " counter=0 go to sleep" << endl;
        pthread_cond_wait(&new_cond, &m_mutexLock);
        if (DEBUG) cout << pthread_self() << " woke up" << endl;
        pthread_cond_destroy(&new_cond);
        // when we come back from wait, we already removed cond from set.
    }
    m_uCounter--;
    if (DEBUG) cout << pthread_self() << " update counter=" << m_uCounter << endl;
    if (DEBUG) cout << pthread_self() << " down() mutex unlock" << endl;
    pthread_mutex_unlock(&m_mutexLock);
}
