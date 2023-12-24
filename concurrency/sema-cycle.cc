#include "sema-cycle.hh"

#include <iostream>

// g++ -std=c++20 -D_LIBCPP_DISABLE_AVAILABILITY sema-cycle.cc -o semacycle

Executor::Executor(int _numWorkers) {
    assert(_numWorkers > 0);
    numWorkers = _numWorkers;
    joinNow = false;

    for (int i = 0; i < numWorkers; i++) {
        Worker * w = new Worker();
        threads.push_back(std::thread(Executor::tf, std::ref(joinNow), w));
        workers.push_back(w);
    }
}

Executor::~Executor() {
    for (int i = 0; i < threads.size(); i++) {
        threads.at(i).join();
    }
    for (int i = 0; i < workers.size(); i++) {
        delete workers.at(i);
    }
}

void Executor::cycle(int iter) {
    assert(iter > 0);
    for (int i = 0; i < iter; i++) {
        for (auto w : workers) {
            w->waker().release();
        }
        for (auto w : workers) {
            w->signal().acquire();
            std::cout << w->getData() << " ";
        }
        std::cout << std::endl << std::endl;
    }
    joinNow = true;
    for (auto w : workers) {
        w->waker().release();
    }
}

void Executor::tf(bool& joinNow, Worker * worker) {
    while (!joinNow) {
        worker->waker().acquire();
        if (joinNow) break;

        worker->work();

        worker->signal().release();
    }
}

int main(void) {
    Executor * e = new Executor(5);
    e->cycle(5);
    delete e;
}
