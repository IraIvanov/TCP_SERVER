#pragma once 

#ifndef offsetof
#define offsetof(type, member) \
            (&((type *)(0))->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
            ((type *)((char *)(ptr) - (int)offsetof(type, member)))
#endif

struct lst_node {
    struct lst_node *next;
    struct lst_node *prev;
};

static inline void lst_init(struct lst_node *node) {
    node->prev = node->next = node;
}

static inline void lst_add_head(struct lst_node *head, struct lst_node *new_node) {
    struct lst_node *next = head->next;
    new_node->prev = head;
    new_node->next = next;
    head->next = new_node;
    next->prev = new_node;
}

static inline void lst_add_tail(struct lst_node *head, struct lst_node *new_node) {
    struct lst_node *prev = head->prev;
    new_node->next = head;
    new_node->prev = prev;
    head->prev = new_node;
    prev->next = new_node;
}

static inline void lst_del(struct lst_node *node) {
    struct lst_node *prev = node->prev, *next = node->next;
    next->prev = prev;
    prev->next = next;
    node->next = node->prev = NULL;
}

#define lst_entry(ptr, type, member) container_of(ptr, type, member)

#define for_each_lst_entry(head, pos, type, member) \
    for (pos = lst_entry(head->next, type, pos); &pos->member != (head); pos = lst_entry(pos->member.next, type, member))

#define for_each_lst_entry_safe(head, pos, n, type, member) \
    for (pos = lst_entry(head->next, type, member), n = lst_entry(pos->member.next, type, member); &pos->member != (head); \
                    pos = n, n = lst_entry(n->member.next, type, member))

static inline int lst_is_empty(struct lst_node *node) {
    return node == node->next;
}