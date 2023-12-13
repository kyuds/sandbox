#include <thread>
#include <condition_variable>
#include <semaphore>
#include <iostream>

// g++ -std=c++20 -D_LIBCPP_DISABLE_AVAILABILITY cycle.cc -o a

// learning objectives:
// - maintain threads to avoid thread creation overhead
// - used in my other project, Praph

void cycle(std::condition_variable& cv_c, std::mutex& cv_m, std::counting_semaphore<1>& c, bool * status) {
    std::unique_lock<std::mutex> lk(cv_m); 

    while (true) {
        cv_c.wait(lk);
        std::cout << "cycle entered" << std::endl;
        *status = true;
        c.release();
    }
}

int main() {
    std::condition_variable cv_c;
    std::mutex cv_m;
    std::counting_semaphore<1> c{0};
    bool status = false;

    std::thread t(cycle, cv_c, cv_m, c, &status);

    while (true) {
        {
            std::lock_guard<std::mutex> lk(cv_m);
            std::cout << "Notifying..." << std::endl;
        }
        cv_c.notify_all();

        c.acquire();

        std::cout << "Got back status: " << status << std::endl;
    }

    return 0;
}
