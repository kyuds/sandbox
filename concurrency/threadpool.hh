#pragma once

#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// we assume that task_t is malloc'ed, and
// thus will be freed accordingly.
typedef struct {
    void (*task) (void *);
    void *args;
} task_t;

class ThreadPool {
    public:
        ThreadPool(int _numThreads);
        ~ThreadPool();
        static void thread_func(std::mutex& taskMutex, 
                                std::mutex& cv_m, 
                                std::condition_variable& cv_c, 
                                std::deque<task_t*> * taskList,
                                bool& joinNow);
        void AddTask(task_t * t);
        void BatchAddTask(std::vector<task_t*>& tasks);
    private:
        void wakeThreads();

        int numThreads;
        std::vector<std::thread> workers;
        bool joinNow;

        std::mutex taskMutex;
        std::mutex cv_m;
        std::condition_variable cv_c;
        std::deque<task_t*> taskList;
};
