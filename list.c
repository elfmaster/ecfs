/*
 * ECFS (Extended core file snapshot) utility (C) 2014 Ryan O'Neill
 * http://www.bitlackeys.org/#research
 * elfmaster@zoho.com
 */


#include "ecfs.h"

/*
 * Generic doubly linked list for adding any type of data
 * we will use it for storing a list of symbol information.
 */
int insert_item_front(list_t **list, void *data, size_t sz)
{
	node_t *new = malloc(sizeof(node_t));
	if (new == NULL)
		return -1;

	new->data = (desc_t *)heapAlloc(sz);
	memcpy((void *)new->data, (void *)data, sz);

	if ((*list)->head == NULL) { // if its a new list
		(*list)->head = new; // set head to point at 1st node
		(*list)->head->prev = NULL; // prev set to null
		(*list)->head->next = NULL; // next set to null
		(*list)->tail = (*list)->head; // set the tail to the head
	} else {
		new->prev = NULL;  // set prev to null
		new->next = (*list)->head; // link new node with adjecent node (pointed to by head)
		(*list)->head->prev = new; // link adjecent node to new node
		(*list)->head = new;	   // set new head pointer
	} 
	
	return 0;
}

int insert_item_end(list_t **list, void *data, size_t sz)
{
	node_t *new = malloc(sizeof(node_t));
	if (new == NULL)
		return -1;
	node_t *tmp = NULL;
	
	new->data = (void *)heapAlloc(sz);
        memcpy((void *)new->data, (void *)data, sz);

	if ((*list)->head == NULL) {
		(*list)->head = new;
		(*list)->head->prev = NULL;
		(*list)->head->next = NULL;
		(*list)->tail = (*list)->head;
	} else {
		for ((*list)->tail = (*list)->head; (*list)->tail != NULL;) {
			tmp = (*list)->tail;
			(*list)->tail = (*list)->tail->next;
		}
		(*list)->tail = new; 
		tmp->next = (*list)->tail; 
		(*list)->tail->prev = tmp;
		(*list)->tail->next = NULL;
	}

	return 0;
}




		
		
	

