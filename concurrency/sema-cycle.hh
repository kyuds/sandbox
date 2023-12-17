#pragma once

#include <semaphore>
#include <thread>
#include <vector>
#include <utility>

// g++ -std=c++20 -D_LIBCPP_DISABLE_AVAILABILITY sema-cycle.cc -o semacycle

// objectives:
// - designing new multithread model for fixing 
//   Praph and developing multithreaded ACO
// - mitigating against MacOS restrictions on 
//   semaphores

class Executor {
    public:
        class Worker {
            public:
                Worker() { counter = 0; }
                ~Worker() {}

                void work() { counter++; }
                int getData() { return counter; }
                std::counting_semaphore<1>& waker() { return wakeWorker; }
                std::counting_semaphore<1>& signal() { return signalDone; }
            
            private:
                int counter;
                std::counting_semaphore<1> wakeWorker {0};
                std::counting_semaphore<1> signalDone {0};
        };

    public:
        Executor(int _numWorkers);
        ~Executor();

        void cycle();
        static void tf(bool& joinNow, Worker * worker);

    private:
        int numWorkers;
        bool joinNow;
        std::vector<std::thread> threads;
        std::vector<Worker*> workers;
};
