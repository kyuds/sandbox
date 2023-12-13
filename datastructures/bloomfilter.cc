#include <cstdlib>
#include <iostream>
#include <vector>

// g++ -std=c++20 bloomfilter.cc -o bloomfilter

// learning objectives:
// - code out a bloom filter!
// - experience coding a bitmap!
// - code out an extension of a bloom filter with the counting version!
// - practice out templated abstract classes!

// BloomFilter(s) Implementation
template <typename K>
class BloomFilter {
    public:
        virtual void Add(K key) = 0;
        virtual bool Check(K key) = 0;
};

template <typename K>
class RegularBloomFilter : public BloomFilter<K> {
    public:
        // size in bytes --> bitmap length will be 8 * size;
        RegularBloomFilter(int size, std::vector<std::size_t (*)(K)> hashFuncs) {
            mSize = size;
            mBitMap = (uint8_t *) malloc(sizeof(uint8_t) * size);
            for (int i = 0; i < size; i++) {
                *(mBitMap + i) = 0;
            }
            mHashFunc = hashFuncs;
        }
        ~RegularBloomFilter() {
            free(mBitMap);
        }
        void Add(K key) override {
            for (auto f : mHashFunc) {
                int absolutePosition = getPos(key, f);
                int blockNumber = absolutePosition / sizeof(uint8_t);
                int blockPosition = absolutePosition % sizeof(uint8_t);

                *(mBitMap + blockNumber) |= 0x01 << blockPosition;
            }
        }
        bool Check(K key) override {
            for (auto f : mHashFunc) {
                int absolutePosition = getPos(key, f);
                int blockNumber = absolutePosition / sizeof(uint8_t);
                int blockPosition = absolutePosition % sizeof(uint8_t);

                if (!((*(mBitMap + blockNumber) >> blockPosition) & 0x01)) {
                    return false;
                }
            }
            return true;
        }
    private:
        int getPos(K key, std::size_t (*f)(K)) {
            std::size_t hsh = (*f)(key);
            int h = static_cast<int>(hsh);
            return h % mSize;
        }
        int mSize;
        uint8_t * mBitMap;
        std::vector<std::size_t (*)(K)> mHashFunc;
};

template <typename K>
class CountingBloomFilter : public BloomFilter<K> {
    public:
        CountingBloomFilter(int size, std::vector<std::size_t (*)(K)> hashFuncs) {
            mSize = size;
            mCountMap = (unsigned int *) malloc(sizeof(unsigned int) * size);
            mHashFunc = hashFuncs;
        }
        ~CountingBloomFilter() {
            free(mCountMap);
        }
        void Add(K key) override {
            for (auto f : mHashFunc) {
                int pos = getPos(key, f);
                *(mCountMap + pos) += 1;
            }
        }
        bool Check(K key) override {
            for (auto f : mHashFunc) {
                int pos = getPos(key, f);
                if (*(mCountMap + pos) == 0) {
                    return false;
                }
            }
            return true;
        }
        void Remove(K key) {
            if (!Check(key)) {
                std::cout << "Cannot remove non-existing key" << std::endl;
                return;
            }
            for (auto f : mHashFunc) {
                int pos = getPos(key, f);
                *(mCountMap + pos) -= 1;
            }
        }
    private:
        int getPos(K key, std::size_t (*f)(K)) {
            std::size_t hsh = (*f)(key);
            int h = static_cast<int>(hsh);
            return h % mSize;
        }
        int mSize;
        unsigned int * mCountMap;
        std::vector<std::size_t (*)(K)> mHashFunc;
};

// testing logic

std::size_t testHashFunc(int key);
void testCbf(std::vector<std::size_t (*)(int)> f);
void testRbf(std::vector<std::size_t (*)(int)> f);

int main(void) {
    // example with a simple, one hash function bloom filter
    std::vector<std::size_t (*)(int)> f;
    f.push_back(testHashFunc);

    testCbf(f);  
    std::cout << std::endl;
    testRbf(f);
}

std::size_t testHashFunc(int key) {
    return std::hash<int>{}(key);
}

void testCbf(std::vector<std::size_t (*)(int)> f) {
    CountingBloomFilter<int> * cbf = new CountingBloomFilter<int>(10, f);
    std::cout << "Checking key exists for empty counting bloom filter..." << std::endl;
    std::cout << "Key 10 exists: " << cbf->Check(10) << std::endl;
    std::cout << "Adding key 10." << std::endl;
    cbf->Add(10);
    std::cout << "Key 10 exists: " << cbf->Check(10) << std::endl;
    std::cout << "Removing key 10." << std::endl;
    cbf->Remove(10);
    std::cout << "Key 10 exists: " << cbf->Check(10) << std::endl;
    std::cout << "Removing key 10 again." << std::endl;
    cbf->Remove(10);
    delete cbf;
}

void testRbf(std::vector<std::size_t (*)(int)> f) {
    RegularBloomFilter<int> * rbf = new RegularBloomFilter<int>(10, f);
    std::cout << "Checking key exists for empty regular bloom filter..." << std::endl;
    std::cout << "Key 11 exists: " << rbf->Check(11) << std::endl;
    std::cout << "Adding key 11." << std::endl;
    rbf->Add(11);
    std::cout << "Key 11 exists: " << rbf->Check(11) << std::endl;
    delete rbf;
}
