#include "bplustree.hh"

// g++ -std=c++20 bplustree.cc -o bplustree

Node::Node(bool _leaf, int _order) {
    leaf = _leaf;
    order = _order;
}

LeafNode::LeafNode(int _order) : Node(true, _order) {
    nextLeaf = NULL;
}

LeafNode::LeafNode(int _order, std::vector<pair_t> p) : Node(true, _order) {
    kvStore = std::move(p);
}

Node * LeafNode::insert(long key, long val) {
    for (auto p = kvStore.begin(); p != kvStore.end(); p++) {
        if (p->key > key) {
            kvStore.emplace(p, pair_t{ key, val });
            break;
        }
    }
    if (kvStore.size() <= getOrder() * 2) {
        return NULL;
    } else {
        std::vector<pair_t> half;
        half.insert(half.end(), std::make_move_iterator(kvStore.begin() + getOrder()),
                                std::make_move_iterator(kvStore.end()));
        kvStore.erase(kvStore.begin() + getOrder(), kvStore.end());
        LeafNode * newLeaf = new LeafNode(getOrder(), std::move(half));
        
        newLeaf->setNextLeaf(nextLeaf);
        nextLeaf = newLeaf;

        return newLeaf;
    }
}

void LeafNode::remove(long key) {
    for (auto p = kvStore.begin(); p != kvStore.end(); p++) {
        if (p->key == key) {
            kvStore.erase(p);
            return;
        }
    }
}

long LeafNode::getKey(long key) {
    for (auto p = kvStore.begin(); p != kvStore.end(); p++) {
        if (p->key == key) return p->val;
    }
    return NULL;
}

// testing code
void testLeafNode();

int main(void) {
    testLeafNode();
    return 0;
}

void testLeafNode() {

}
