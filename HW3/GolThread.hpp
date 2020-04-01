//
// Created by user on 23/05/2019.
//

#ifndef OS_WET3_GOLTHREAD_H
#define OS_WET3_GOLTHREAD_H

#include "Headers.hpp"
#include "Task.hpp"
#include "RevSem.hpp"
#include "PCQueue.hpp"
#include "Thread.hpp"


class GolThread : public Thread {
public:
    GolThread(uint id, PCQueue<Task> &task_queue, vector<tile_record> &tile_hist,
              pthread_mutex_t &mutex_lock, RevSem &rev_sem);

    ~GolThread() = default;

    void thread_workload() override;

    void push_job() {}

private:
    PCQueue<Task> &m_task_queue;
    vector<tile_record> &m_tile_hist;
    pthread_mutex_t &m_mutex_lock;
    RevSem &m_rev_sem;

};


#endif //OS_WET3_GOLTHREAD_H
