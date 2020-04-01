//
// Created by user on 23/05/2019.
//

#include "GolThread.hpp"


GolThread::GolThread(uint id, PCQueue<Task> &task_queue, vector<tile_record> &tile_hist,
                     pthread_mutex_t &mutex_lock, RevSem &rev_sem) : Thread(id),
                                                                           m_task_queue(task_queue),
                                                                           m_tile_hist(tile_hist),
                                                                           m_mutex_lock(mutex_lock),
                                                                           m_rev_sem(rev_sem) {}

void GolThread::thread_workload() {
    while (true) {
        Task t = m_task_queue.pop();
        if (t.isPoison()) {
            break;
        }

        auto gen_start = std::chrono::system_clock::now();
        t.exe(); // Execute the task.
        auto gen_end = std::chrono::system_clock::now();

        pthread_mutex_lock(&m_mutex_lock);
        tile_record tr;
        tr.tile_compute_time = (double) std::chrono::duration_cast<std::chrono::microseconds>(
                gen_end - gen_start).count();
        tr.thread_id = m_thread_id;
        m_tile_hist.push_back(tr);
        pthread_mutex_unlock(&m_mutex_lock);
        m_rev_sem.post(); //TODO maybe put it inside lock ?
    }
    pthread_exit(nullptr);

}

