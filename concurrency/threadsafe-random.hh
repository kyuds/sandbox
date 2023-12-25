#pragma once

#include <random>
#include <string>

// g++ -std=c++20 threadsafe-random.cc -o tsr

// objective:
// - randomize distribution in an organized way
//   such that random number generation across
//   threads is thread safe and deterministic
// - use case: ant colony optimization.
//   different ants need different random number
//   generation.

class Randomizer {
    public:
        Randomizer(int _i);
        ~Randomizer() {}

        void printGenRandom();
        void work();

    private:
        std::string ret;
        std::mt19937_64 generator;
        std::uniform_real_distribution<double> r;
};

void thread_func(Randomizer * r) {
    r->work();
}
