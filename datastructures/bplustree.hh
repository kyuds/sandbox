#ifndef BPLUSTREE
#define BPLUSTREE

#include <iterator>
#include <optional>
#include <vector>

class Node;
class LeafNode;
class InnerNode;

typedef struct {
    long key;
    long val;
} pair_t;

class BPlusTree {
    public:
        BPlusTree(int _order);
        // bulk load
        BPlusTree(int _order, int fill, std::vector<pair_t>& data);
        ~BPlusTree();

        void put(long key, long val);
        void remove(long key);

        std::optional<long> get(long key);
        long getOrDefault(long key, long def);

        int getOrder() { return order; }
        int getHeight();

        void print();

    private:
        int order;
        Node * root;
    
    // iterator implementation
    public:
        class iterator : public std::iterator<
                                    std::input_iterator_tag,
                                    pair_t,
                                    int,
                                    const pair_t *,
                                    pair_t&
                                > {
            public:
                explicit iterator(bool _end, Node * root);
                iterator& operator++();
                const iterator operator++(int);
                bool operator==(iterator other) const;
                bool operator!=(iterator other) const;
                reference operator*() const;
                pair_t * operator->();
            private:
                LeafNode * curr;
                int num;
                bool end;
        };
        iterator begin() { return iterator(false, root); }
        iterator end() { return iterator(true, root); }
};

class Node {
    public:
        Node(bool _leaf, int _order);
        virtual ~Node() {}

        bool isLeaf() { return leaf; }
        int getOrder() { return order; }
        virtual int getHeight() = 0;

        virtual LeafNode * get(long key) = 0;
        virtual LeafNode * getLeftMost() = 0;

        virtual std::optional<std::pair<Node*, long>> put(long key, long val) = 0;
        virtual std::optional<std::pair<Node*, long>> bulk(std::vector<pair_t>& data,
                                                           int& idx,
                                                           int fill) = 0;
        virtual bool remove(long key) = 0;

        virtual void print(int offset) = 0;
        
    private:
        bool leaf;
        int order;
};

class InnerNode : public Node {
    public:
        InnerNode(int _order,
                  std::vector<long> _keys, 
                  std::vector<Node *> _nodes);
        ~InnerNode();

        LeafNode * get(long key) override;
        LeafNode * getLeftMost() override;
        int getHeight() override { return height; }

        std::optional<std::pair<Node*, long>> put(long key, long val) override;
        std::optional<std::pair<Node*, long>> bulk(std::vector<pair_t>& data,
                                                   int& idx,
                                                   int fill) override;
        bool remove(long key) override;

        void print(int offset) override;

    private:
        Node * findRelevantNode(long key);

        int height;
        std::vector<long> keys;
        std::vector<Node *> nodes;
};

class LeafNode : public Node {
    public:
        LeafNode(int _order);
        LeafNode(int _order, std::vector<pair_t> p);
        ~LeafNode() {}

        LeafNode * get(long key) override { return this; }
        LeafNode * getLeftMost() override { return this; }
        int getHeight() override { return 1; }

        std::optional<std::pair<Node*, long>> put(long key, long val) override;
        std::optional<std::pair<Node*, long>> bulk(std::vector<pair_t>& data,
                                                   int& idx,
                                                   int fill) override;
        bool remove(long key) override;

        void print(int offset) override;

        std::optional<long> getKey(long key);
        LeafNode * getNextLeaf() { return nextLeaf; }
        void setNextLeaf(LeafNode * ln) { nextLeaf = ln; }

        std::vector<pair_t>& getKeys() { return kvStore; }

        // for iterator
        int size() { return kvStore.size(); }
        pair_t & getByIdx(int i) { return kvStore.at(i); }
    
    private:
        LeafNode * nextLeaf;
        std::vector<pair_t> kvStore;
};

#endif
