//
// Created by user on 13/05/2019.
//
#include "RevSem.hpp"

RevSem::~RevSem() {
    if (DEBUG) cout << "DESTROY" << endl;
    while (!m_waitQueue.empty()) {
        pthread_cond_destroy(m_waitQueue.front());
        m_waitQueue.pop();
    }
    while (!m_postQueue.empty()) {
        pthread_cond_destroy(m_postQueue.front());
        m_postQueue.pop();
    }
    pthread_mutex_destroy(&m_mutexLock);
    pthread_mutexattr_destroy(&m_mutexAttr);
}

void RevSem::initRevSem(uint val) {

    m_num_post_to_wait = val;
    m_uCounter = val;

    if (DEBUG) cout << "INIT counter=" << val << endl;
    pthread_mutexattr_init(&m_mutexAttr);
    pthread_mutexattr_settype(&m_mutexAttr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&m_mutexLock, &m_mutexAttr);
    // m_waitQueue and m_postQueue is constructed automatically
}

void RevSem::wait() {
    pthread_mutex_lock(&m_mutexLock);
    if (DEBUG) cout << pthread_self() << " wait() mutex lock" << endl;
    uint num_to_wake_up = m_postQueue.size() < m_num_post_to_wait ? m_postQueue.size() : m_num_post_to_wait;
    if (num_to_wake_up > 0) {
        if (DEBUG) cout << pthread_self() << " wake up " << num_to_wake_up << " post signal calls" << endl;
        for (uint i = 0; i < num_to_wake_up; ++i) {
            pthread_cond_signal(m_postQueue.front());
            m_postQueue.pop();
        }
    }
    while (m_uCounter > 0) {
        pthread_cond_t new_cond;
        pthread_cond_init(&new_cond, nullptr);
        m_waitQueue.push(&new_cond);
        if (DEBUG) cout << pthread_self() << " counter>0 go to sleep" << endl;
        pthread_cond_wait(&new_cond, &m_mutexLock);
        if (DEBUG) cout << pthread_self() << " wait call woke up" << endl;
        pthread_cond_destroy(&new_cond);
        // when we come back from wait, we already removed cond from set.
    }
    m_uCounter = m_num_post_to_wait;
    if (DEBUG) cout << pthread_self() << " update counter=" << m_uCounter << endl;
    if (DEBUG) cout << pthread_self() << " wait() mutex unlock" << endl;
    pthread_mutex_unlock(&m_mutexLock);
}

void RevSem::post() {
    pthread_mutex_lock(&m_mutexLock);
    if (DEBUG) cout << pthread_self() << " post() mutex lock" << endl;
    while (m_waitQueue.empty()) {
        pthread_cond_t new_cond;
        pthread_cond_init(&new_cond, nullptr);
        m_postQueue.push(&new_cond);
        if (DEBUG) cout << pthread_self() << " no wait calls, go to sleep" << endl;
        pthread_cond_wait(&new_cond, &m_mutexLock);
        if (DEBUG) cout << pthread_self() << " post signal call woke up" << endl;
        pthread_cond_destroy(&new_cond);
    }
    m_uCounter--;
    if (DEBUG) cout << pthread_self() << " update counter=" << m_uCounter << endl;
    if (m_uCounter == 0) {
        if (DEBUG) cout << pthread_self() << " wake up a wait call" << endl;
        pthread_cond_signal(m_waitQueue.front());
        m_waitQueue.pop();
    } else if (!m_waitQueue.empty()) {
        if (DEBUG) cout << pthread_self() << " havn't got required signals" << endl;
    }
    if (DEBUG) cout << pthread_self() << " post() mutex unlock" << endl;
    pthread_mutex_unlock(&m_mutexLock);
}


