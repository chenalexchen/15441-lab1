/** @file list.h
 *  @brief define various double linked list routine to use
 *
 *  This file is basically from linux "include/linux/list.h". We modify
 *  (reuse) the code in our kernel source. We can write our own, given 
 *  this header file, but we would like to give credit to linux authors
 *  
 *  @author Chen Chen(chenche1) & Henggang Cui(henganc)
 *  @bug no known bug
 */
#ifndef __LIST_H_
#define __LIST_H_

#include "stddef.h"


#define LIST_POISON1 0xdeadbeef
#define LIST_POISON2 0xbeefdead


struct list_head {
    struct list_head *prev, *next;
};


//#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/** 
 * @brief cast a member of a structure out to the containing structure 
 * @param ptr        the pointer to the member. 
 * @param type       the type of the container struct this is embedded in. 
 * @param member     the name of the member within the struct. 
 * 
 */ 
#define container_of(ptr, type, member) ({                      \
   const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
   (type *)( (char *)__mptr - offsetof(type,member) );}) 


#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
   struct list_head name = LIST_HEAD_INIT(name)


static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __list_add(struct list_head *new,
                               struct list_head *prev,
                               struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

/**
 * @brief list_add - add a new entry
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 *
 * @param new new entry to be added
 * @param head list head to add it after
 * @return Void
 */
static inline void list_add(struct list_head *new, struct list_head *head)
{
    __list_add(new, head, head->next);
}


/**
 * @brief list_add_tail - add a new entry
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 * @param new new entry to be added
 * @param head list head to add it before
 * @return Void
 */
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    __list_add(new, head->prev, head);
}


/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
 static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}


static inline void __list_del_entry(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
}


/**
 * @brief list_del - deletes entry from list.
 * 
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 *
 *  @param entry the element to delete from the list.
 *  @return Void
 */
static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = (struct list_head *)LIST_POISON1;
    entry->prev = (struct list_head *)LIST_POISON2;
}


/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(const struct list_head *head)
{
    return head->next == head;
}


/**
 * list_entry - get the struct for this entry
 * @ptr:        the &struct list_head pointer.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
  container_of(ptr, type, member)

/**
 * @brief list_for_each_entry  -       iterate over list of given type
 * @param pos        the type * to use as a loop cursor.
 * @param head       the head for your list.
 * @param member     the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)                          \
  for (pos = list_entry((head)->next, typeof(*pos), member);        \
       &pos->member != (head);                        \
       pos = list_entry(pos->member.next, typeof(*pos), member))


/**
 * @brief iterate over list of given type safe against removal of list entry
 *
 * @param pos        the type * to use as a loop cursor.
 * @param n          another type * to use as temporary storage
 * @param head       the head for your list.
 * @param member     the name of the list_struct within the struct.
 **/
#define list_for_each_entry_safe(pos, n, head, member)                  \
    for (pos = list_entry((head)->next, typeof(*pos), member),          \
             n = list_entry(pos->member.next, typeof(*pos), member);    \
         &pos->member != (head);                                        \
         pos = n, n = list_entry(n->member.next, typeof(*n), member))   


/**
 * list_first_entry - get the first element from a list
 * @param ptr        the list head to take the element from.
 * @param type       the type of the struct this is embedded in.
 * @param member     the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member)    \
    list_entry((ptr)->next, type, member)



static inline void __list_splice(struct list_head *list,
                 struct list_head *head)
{
    struct list_head *first = list->next;
    struct list_head *last = list->prev;
    struct list_head *at = head->next;

    first->prev = head;
    head->next = first;

    last->next = at;
    at->prev = last;
}

/**
 * list_splice - join two lists
 * @param list the new list to add.
 * @param head the place to add it in the first list.
 */
static inline void list_splice(struct list_head *list, struct list_head *head)
{
    if (!list_empty(list))
        __list_splice(list, head);
}


static inline int list_has_only_entry(struct list_head *list)
{
    return (!list_empty(list) && (list->next->next == list) );
}

/**
 * list_splice_init - join two lists and reinitialise the emptied list.
 * @param list the new list to add.
 * @param head the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
static inline void list_splice_init(struct list_head *list,
                    struct list_head *head)
{
    if (!list_empty(list)) {
        __list_splice(list, head);
        INIT_LIST_HEAD(list);
    }
}




#endif /* end of __LIST_H_ */

