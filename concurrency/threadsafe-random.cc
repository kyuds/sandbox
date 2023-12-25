#include "threadsafe-random.hh"

#include <iostream>
#include <thread>
#include <vector>

int main(void) {
    std::vector<Randomizer*> r;
    std::vector<std::thread> t;

    for (int i = 0; i < 10; i++) {
        Randomizer * rnd = new Randomizer(i);
        r.push_back(rnd);
        t.push_back(std::thread(thread_func, rnd));
    }

    for (int i = 0; i < 10; i++) {
        t.at(i).join();
    }

    for (auto rnd : r) {
        rnd->printGenRandom();
    }
}

Randomizer::Randomizer(int _i) {
    // generate a random distribution based on _i;
    generator = std::mt19937_64(_i);
    r = std::uniform_real_distribution<double>(0.0, 1.0);
}

void Randomizer::work() {
    // generate 10 random numbers and convert to string and store.
    for (int i = 0; i < 10; i++) {
        ret = ret + std::to_string(r(generator)) + std::string(" ");
    }
}

void Randomizer::printGenRandom() {
    std::cout << ret << std::endl;
}
