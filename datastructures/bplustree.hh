#ifndef BPLUSTREE
#define BPLUSTREE

#include <vector>

class Node;
class LeafNode;
class InnerNode;

typedef struct {
    long key;
    long val;
} pair_t;

// class BPlusTree {
//     public:
//         BPlusTree(int _order);
//         BPlusTree(int _order, std::vector<long>& keys, std::vector<long>& vals);
//         ~BPlusTree();

//         void insert(long key, long val);
//         void remove(long key);

//         long get(long key);
//         long getOrDefault(long key, long val);

//         int getOrder();
//         int getHeight();

//         // iterator stuff
    
//     private:
//         int order;
//         int height;
//         Node * root;
// };

class Node {
    public:
        Node(bool _leaf, int _order);
        virtual ~Node() {}

        bool isLeaf() { return leaf; }
        int getOrder() { return order; }

        virtual LeafNode * get(long key) = 0;
        virtual LeafNode * getLeftMost() = 0;

        virtual Node * insert(long key, long val) = 0;
        virtual void remove(long key) = 0;
        
    private:
        bool leaf;
        int order;
};

// class InnerNode : public Node {
//     public:
//         InnerNode(int _order);
//         ~InnerNode();

//         LeafNode * get(long key) override;
//         LeafNode * getLeftMost() override;

//         void insert(long key, long val) override;
//         void remove(long key) override;
//     private:

// };

class LeafNode : public Node {
    public:
        LeafNode(int _order);
        LeafNode(int _order, std::vector<pair_t> p);
        ~LeafNode() {}

        LeafNode * get(long key) override { return this; }
        LeafNode * getLeftMost() override { return this; }

        Node * insert(long key, long val) override;
        void remove(long key) override;

        long getKey(long key);
        LeafNode * getNextLeaf() { return nextLeaf; }
        void setNextLeaf(LeafNode * ln) { nextLeaf = ln; }

        std::vector<pair_t>& getKeys() { return kvStore; }
    
    private:
        LeafNode * nextLeaf;
        std::vector<pair_t> kvStore;
};

#endif
