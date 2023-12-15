#include "bplustree.hh"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <utility>

// g++ -std=c++20 bplustree.cc -o bplustree

// learning objectives:
// - write a bit more complicated datastructure in C++!
// - learn about custom C++ iterators!

BPlusTree::BPlusTree(int _order) {
    assert(_order > 0);
    order = _order;
    root = (Node *) new LeafNode(order);
}

BPlusTree::BPlusTree(int _order, int fill, std::vector<pair_t>& data) {
    assert(_order > 0);
    assert(fill <= _order * 2);
    order = _order;
    root = (Node *) new LeafNode(order);

    int idx = 0;
    while (idx < data.size()) {
        auto ret = root->bulk(data, idx, fill);
        if (ret.has_value()) {
            std::vector<long> k;
            std::vector<Node*> n;
            k.push_back(ret.value().second);
            n.push_back(root);
            n.push_back(ret.value().first);

            root = (Node *) new InnerNode(order, k, n);
        }
    }
}

BPlusTree::~BPlusTree() { delete root;}
int BPlusTree::getHeight() { return root->getHeight(); }
void BPlusTree::print() { root->print(0); }

void BPlusTree::put(long key, long val) {
    auto r = root->put(key, val);
    if (r.has_value()) {
        Node * nd = r.value().first;
        long sepKey = r.value().second;
        std::vector<Node *> nodes;
        nodes.push_back(root);
        nodes.push_back(nd);
        std::vector<long> keys;
        keys.push_back(sepKey);
        root = (Node *) new InnerNode(order, std::move(keys), std::move(nodes));
    }
}

void BPlusTree::remove(long key) {
    root->remove(key);
}

std::optional<long> BPlusTree::get(long key) {
    LeafNode * ln = root->get(key);
    return ln->getKey(key);
}

long BPlusTree::getOrDefault(long key, long def) {
    auto ret = get(key);
    if (ret.has_value()) {
        return *ret;
    }
    return def;
}

Node::Node(bool _leaf, int _order) {
    leaf = _leaf;
    order = _order;
}

LeafNode::LeafNode(int _order) : Node(true, _order) {
    nextLeaf = NULL;
}

LeafNode::LeafNode(int _order, std::vector<pair_t> p) : Node(true, _order) {
    kvStore = std::move(p);
    nextLeaf = NULL;
}

std::optional<std::pair<Node*, long>> LeafNode::put(long key, long val) {
    bool success = false;
    for (auto p = kvStore.begin(); p != kvStore.end(); p++) {
        if (p->key == key) {
            success = true;
            p->val = val;
            break;
        }
        if (p->key > key) {
            success = true;
            kvStore.emplace(p, pair_t{ key, val });
            break;
        }
    }
    if (!success) kvStore.push_back(pair_t{ key, val });

    if (kvStore.size() <= getOrder() * 2) {
        return std::nullopt;
    } else {
        std::vector<pair_t> half;
        half.insert(half.end(), std::make_move_iterator(kvStore.begin() + getOrder()),
                                std::make_move_iterator(kvStore.end()));
        kvStore.erase(kvStore.begin() + getOrder(), kvStore.end());
        long sepKey = half.at(0).key;
        LeafNode * newLeaf = new LeafNode(getOrder(), std::move(half));
        
        newLeaf->setNextLeaf(nextLeaf);
        nextLeaf = newLeaf;

        return std::make_pair(newLeaf, sepKey);
    }
}

std::optional<std::pair<Node*, long>> LeafNode::bulk(std::vector<pair_t>& data,
                                                     int& idx,
                                                     int fill) {
    assert(kvStore.size() == 0);
    int i = 0;
    while (idx < data.size() && i++ < fill) {
        kvStore.push_back(data.at(idx++));
    }
    if (idx < data.size()) {
        long sepKey = data.at(idx).key;
        nextLeaf = new LeafNode(getOrder());
        return std::make_pair(nextLeaf, sepKey);
    }
    return std::nullopt;
}

bool LeafNode::remove(long key) {
    for (auto p = kvStore.begin(); p != kvStore.end(); p++) {
        if (p->key == key) {
            kvStore.erase(p);
            return true;
        }
    }
    return false;
}

std::optional<long> LeafNode::getKey(long key) {
    for (auto p = kvStore.begin(); p != kvStore.end(); p++) {
        if (p->key == key) return p->val;
    }
    return std::nullopt;
}

void LeafNode::print(int offset) {
    for (auto p = kvStore.begin(); p != kvStore.end(); p++) {
        std::cout << std::string(offset, ' ');
        std::cout << "(" << p->key << ", " << p->val << ")" << std::endl;
    }
}

InnerNode::InnerNode(int _order,
                     std::vector<long> _keys, 
                     std::vector<Node *> _nodes) : Node(false, _order) {
    assert(_nodes.size() - _keys.size() == 1 && _nodes.size() > 0);
    keys = std::move(_keys);
    nodes = std::move(_nodes);
    height = 0;
    for (auto n = nodes.begin(); n != nodes.end(); n++) {
        height = std::max(height, (*n)->getHeight() + 1);
    }
}

InnerNode::~InnerNode() {
    for (int i = 0; i < nodes.size(); i++) {
        delete nodes.at(i);
    }
}

LeafNode * InnerNode::get(long key) {
    Node * n = findRelevantNode(key);
    return n->get(key);
}

LeafNode * InnerNode::getLeftMost() {
    return nodes.at(0)->getLeftMost();
}

std::optional<std::pair<Node*, long>> InnerNode::put(long key, long val) {
    Node * n = findRelevantNode(key);
    auto ret = n->put(key, val);

    if (ret.has_value()) {
        Node * nd = ret.value().first;
        long sepKey = ret.value().second;

        auto n = nodes.begin() + 1;
        bool success = false;
        for (auto k = keys.begin(); k != keys.end(); k++) {
            if (*k > sepKey) {
                keys.emplace(k, sepKey);
                nodes.emplace(n, nd);
                success = true;
                break;
            }
        }
        if (!success) {
            keys.emplace(keys.end(), sepKey);
            nodes.emplace(nodes.end(), nd);
        }
        if (keys.size() <= getOrder() * 2) {
            return std::nullopt;
        }
        std::vector<long> skeys;
        long promote = *(keys.begin() + getOrder());
        skeys.insert(skeys.end(), std::make_move_iterator(keys.begin() + getOrder() + 1),
                                  std::make_move_iterator(keys.end()));
        keys.erase(keys.begin() + getOrder(), keys.end());
        std::vector<Node*> snodes;
        snodes.insert(snodes.end(), std::make_move_iterator(nodes.begin() + getOrder() + 1),
                                    std::make_move_iterator(nodes.end()));
        nodes.erase(nodes.begin() + getOrder() + 1, nodes.end());
        Node * newInner = new InnerNode(getOrder(), std::move(skeys), std::move(snodes));

        return std::make_pair(newInner, promote);
    }
    return std::nullopt;
}

std::optional<std::pair<Node*, long>> InnerNode::bulk(std::vector<pair_t>& data,
                                                      int& idx,
                                                      int fill) {
    while (idx < data.size() && keys.size() <= getOrder() * 2) {
        auto ret = nodes.at(nodes.size() - 1)->bulk(data, idx, fill);
        if (ret.has_value()) {
            keys.push_back(ret.value().second);
            nodes.push_back(ret.value().first);
        }
    }
    if (keys.size() <= getOrder() * 2) {
        return std::nullopt;
    }
    std::vector<long> skeys;
    long promote = *(keys.begin() + getOrder());
    skeys.insert(skeys.end(), std::make_move_iterator(keys.begin() + getOrder() + 1),
                              std::make_move_iterator(keys.end()));
    keys.erase(keys.begin() + getOrder(), keys.end());
    std::vector<Node*> snodes;
    snodes.insert(snodes.end(), std::make_move_iterator(nodes.begin() + getOrder() + 1),
                                std::make_move_iterator(nodes.end()));
    nodes.erase(nodes.begin() + getOrder() + 1, nodes.end());
    Node * newInner = new InnerNode(getOrder(), std::move(skeys), std::move(snodes));

    return std::make_pair(newInner, promote);
}

bool InnerNode::remove(long key) {
    Node * n = findRelevantNode(key);
    return n->remove(key);
}

Node * InnerNode::findRelevantNode(long key) {
    assert(nodes.size() - keys.size() == 1 && nodes.size() > 0);

    int idx = 0;
    for (auto k = keys.begin(); k != keys.end(); k++) {
        if (*k > key) break;
        idx += 1;
    }
    return nodes.at(idx);
}

void InnerNode::print(int offset) {
    auto n = nodes.begin();
    (*n)->print(offset + 2);
    for (auto k = keys.begin(); k != keys.end(); k++) {
        std::cout << std::string(offset, ' ');
        std::cout << *k << std::endl;
        (*++n)->print(offset + 2);
    }
}

BPlusTree::iterator::iterator(bool _end, Node * root) {
    end = _end;
    curr = root->getLeftMost();
    num = 0;
}

BPlusTree::iterator& BPlusTree::iterator::operator++() {
    if (end) {
        return *this;
    }
    num++;
    if (num >= curr->size()) {
        num = 0;
        curr = curr->getNextLeaf();
        if (curr == NULL) end = true;
    }
    return *this;
}

const BPlusTree::iterator BPlusTree::iterator::operator++(int) {
    iterator ret = *this;
    ++(*this);
    return ret;
}

bool BPlusTree::iterator::operator==(iterator other) const {
    if (end || other.end) return end && other.end;
    return curr == other.curr && num == other.num;
}

bool BPlusTree::iterator::operator!=(iterator other) const {
    if (end || other.end) return end != other.end;
    return curr != other.curr || num != other.num;
}

pair_t& BPlusTree::iterator::operator*() const {
    return curr->getByIdx(num);
}

pair_t * BPlusTree::iterator::operator->() {
    return &curr->getByIdx(num);
}

// testing code
void testLeafNode();
void testInnerNode();
void testBPlusTree();
void testIterator();
void testLeafBulk();
void testBulk();

int main(void) {
    testBulk();
    return 0;
}

void testBulk() {
    std::vector<pair_t> data;
    for (int i = 0; i < 30; i++) {
        data.push_back(pair_t{(long) i, (long) i});
    }
    BPlusTree * bt = new BPlusTree(2, 3, data);
    bt->put(6L, 3L);
    bt->print();
    int x = 0;
    for (auto i = bt->begin(); i != bt->end(); i++) {
        assert(i->key == x++);
        std::cout << i->key << " ";
    }
}

void testLeafBulk() {
    std::vector<pair_t> data;
    for (int i = 0; i < 4; i++) {
        data.push_back(pair_t{(long) i, (long) i});
    }
    LeafNode * nd = new LeafNode(2);
    int idx = 0;
    auto ret = nd->bulk(data, idx, 3);
    assert(ret.has_value());
    assert(nd->getKey(0L).has_value());
    assert(!nd->getKey(3L).has_value());
    assert(idx == 3);
}

void testIterator() {
    auto bt = new BPlusTree(2);
    for (int i = 0; i < 30; i++) {
        bt->put((long) i, (long) i);
    }
    long x = 0L;
    for (auto i = bt->begin(); i != bt->end(); i++) {
        assert(i->key == x);
        x++;
        std::cout << i->key << " ";
    }
    std::cout << std::endl << std::endl;
    bt->print();
}

void testBPlusTree() {
    auto bt = new BPlusTree(2);
    for (int i = 0; i < 30; i++) {
        bt->put((long) i, (long) i);
    }
    bt->remove(14);
    bt->remove(15);
    bt->print();
}

void testLeafNode() {
    // ord = 2; max keys = 4
    LeafNode * nd = new LeafNode(2);
    for (int i = 0; i < 16; i += 4) {
        // adding four keys -- check they don't split
        assert(!nd->put((long) i, (long) i).has_value());
    }
    // add one more key -- check they split
    auto ret = nd->put((long) 2, (long) 2);
    assert(ret.has_value());
    // keys: 0, 2, 4, 8, 12 --> 0, 2 | 4, 8, 12
    assert(ret->second == 4);
    for (int i = 0; i <= 2; i += 2) {
        assert(nd->getKey((long) i).has_value());
    }
    assert(!nd->getKey(4L).has_value());
    LeafNode * split = (LeafNode *) ret.value().first;
    for (int i = 4; i <= 12; i += 4) {
        assert(split->getKey((long) i).has_value());
    }
    assert(!split->getKey(2L).has_value());

    assert(nd->getNextLeaf() == split);
}

void testInnerNode() {
    LeafNode * n1 = new LeafNode(2);
    for (int i = 0; i < 16; i += 4) {
        n1->put((long) i, (long) i);
    }

    std::vector<Node *> nodes;
    nodes.push_back((Node *) n1);
    InnerNode * i = new InnerNode(2, std::vector<long>(), std::move(nodes));

    for (int x = 0; x < 20; x++) {
        long t = (long) (x * 2) + 1;
        auto r = i->put(t, t);
        if (r.has_value()) {
            r.value().first->print(0);
            break;
        }
    }
    i->remove(8L);
    i->print(0);
}
