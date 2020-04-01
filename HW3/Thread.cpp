//
// Created by user on 23/05/2019.
//
#include "Thread.hpp"


Thread::Thread(uint thread_id) : m_thread_id(thread_id)
{
    // Only places thread_id
}

Thread::~Thread() {}

bool Thread::start() {
    return pthread_create(&m_thread, nullptr, entry_func, (void*)this) == 0;
}

void Thread::join() {
    pthread_join(m_thread, nullptr);
}

uint Thread::thread_id() {
    return m_thread_id;
}

void *Thread::entry_func(void *thread) { ((Thread *)thread)->thread_workload(); return NULL; }
