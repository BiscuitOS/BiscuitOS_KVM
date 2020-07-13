#ifndef _BISCUITOS_LIST_H
#define _BISCUITOS_LIST_H

#include <linux/list.h>

/**
 * hlist_for_each_entry - iterate over list of given type
 * @tpos:       the type * to use as a loop cursor.
 * @pos:        the &struct hlist_node to use as a loop cursor.
 * @head:       the head for your list.
 * @member:     the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_bs(tpos, pos, head, member)		\
	for (pos = (head)->first;					\
	     pos && ({ prefetch(pos->next); 1;}) &&			\
	    ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

#endif
