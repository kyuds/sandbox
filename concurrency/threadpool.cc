#include "threadpool.hh"

#include <chrono>
#include <cstdlib>
#include <iostream>

// g++ -std=c++20 threadpool.cc -o threadpool

// learning objectives
// - review thread pooling from CS 162 @ Berkeley!

// ThreadPool implementation
ThreadPool::ThreadPool(int _numThreads) {
    numThreads = _numThreads;
    joinNow = false;

    for (int i = 0; i < numThreads; i++) {
        std::thread t(thread_func,
                      std::ref(taskMutex),
                      std::ref(cv_m),
                      std::ref(cv_c),
                      &taskList,
                      std::ref(joinNow));
        workers.push_back(std::move(t));
    }
}

ThreadPool::~ThreadPool() {
    joinNow = true;
    wakeThreads();
    for (int i = 0; i < workers.size(); i++) {
        workers.at(i).join();
    }
    for (int i = 0; i < taskList.size(); i++) {
        free(taskList.at(i));
    }
}

void ThreadPool::thread_func(std::mutex& taskMutex, 
                 std::mutex& cv_m, 
                 std::condition_variable& cv_c, 
                 std::deque<task_t*> * taskList,
                 bool& joinNow) {
    std::unique_lock<std::mutex> lk(cv_m, std::defer_lock);
    while (true) {
        if (joinNow) break;
        lk.lock();
        while (taskList->empty()) {
            cv_c.wait(lk);
        }
        if (joinNow) {
            lk.unlock();
            cv_c.notify_all();
            break;
        }
        taskMutex.lock();
        if (taskList->empty()) {
            taskMutex.unlock();
            continue;
        }
        task_t * t = taskList->front();
        taskList->pop_front();
        taskMutex.unlock();
        
        lk.unlock();

        (t->task)(t->args);
        free(t);
    }
}

void ThreadPool::AddTask(task_t * t) {
    taskMutex.lock();
    bool signal = false;
    if (taskList.empty()) signal = true;
    taskList.push_back(t);
    if (signal) wakeThreads();
    taskMutex.unlock();
}

void ThreadPool::BatchAddTask(std::vector<task_t*>& tasks) {
    for (auto t : tasks) {
        AddTask(t);
    }
}

void ThreadPool::wakeThreads() {
    { std::lock_guard<std::mutex> lk(cv_m); }
    cv_c.notify_all();
}

// Testing Implementation
void sample_task(void * args) {
    std::cout << "Task Started: " << std::this_thread::get_id() << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(2));
}

int main(void) {
    ThreadPool * tp = new ThreadPool(3);

    std::vector<task_t*> tsks;

    for (int i = 0; i < 9; i++) {
        task_t * t = (task_t *) malloc(sizeof(task_t));
        t->task = sample_task;
        t->args = NULL;
        tsks.push_back(t);
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
    tp->BatchAddTask(tsks);
    std::this_thread::sleep_for(std::chrono::seconds(9));

    tsks.clear();
    for (int i = 0; i < 9; i++) {
        task_t * t = (task_t *) malloc(sizeof(task_t));
        t->task = sample_task;
        t->args = NULL;
        tsks.push_back(t);
    }
    tp->BatchAddTask(tsks);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    delete tp;

    return 0;
}
