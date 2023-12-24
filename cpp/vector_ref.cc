#include <iostream>
#include <vector>

// g++ vector_ref.cc -o r

// making sure std::vector copy by value semantics

void p(std::vector<int>& v) {
    for (int i = 0; i < v.size(); i++) {
        std::cout << v.at(i) << " ";
    }
    std::cout << std::endl;
}

int main(void) {
    std::vector<int> a;
    a.push_back(0);
    a.push_back(0);
    a.push_back(0);
    a.push_back(0);
    a.push_back(0);

    p(a);
    std::vector<int>& b = a;
    p(b);

    std::vector<int> c = b;
    c.push_back(1);
    p(a);
    p(b);
    p(c);

    return 0;
}