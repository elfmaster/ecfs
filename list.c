/*
 * ECFS (Extended core file snapshot) utility (C) 2014 Ryan O'Neill
 * http://www.bitlackeys.org/#research
 * elfmaster@zoho.com
 */


#include "ecfs.h"

int insert_front(list_t **list, desc_t *desc)
{
	node_t *new = malloc(sizeof(node_t));
	if (new == NULL)
		return -1;

	node_t *tmp;

	new->desc = (desc_t *)heapAlloc(sizeof(desc_t));
	memcpy((void *)new->desc, (void *)desc, sizeof(desc_t));

	if ((*list)->head == NULL) {
		(*list)->head = new;
		(*list)->head->prev = NULL;
		(*list)->head->next = NULL;
		(*list)->tail = (*list)->head;
	} else {
		tmp = new;
		tmp->prev = NULL;
		tmp->next = (*list)->head;
		(*list)->head->prev = tmp;
		(*list)->head = tmp;
	} 
	
	return 0;
}

int delete_node_by_pid(list_t **list, pid_t pid)
{
	node_t *current;
	for (current = (*list)->head; current != NULL; current = current->next) {
		if (current->desc->memory.pid) {
			if ((*list)->head == current)
				(*list)->head = current->next;
			current->prev->next = current->next;
			current->next->prev = current->prev;
		}
	}
	
	return 0;
}

int reverse_list(list_t **list)
{
	node_t *tmp = NULL;
	node_t *current = (*list)->head;
	while (current != NULL) {
		tmp = current->prev;
		current->prev = current->next;
		current->next = tmp;
		current = current->prev;
	}
	if (tmp != NULL)
		(*list)->head = tmp->prev; //incase the list is only 1 node
}

		
int insert_end(list_t **list, desc_t *desc)
{
	node_t *new = malloc(sizeof(node_t));
	if (new == NULL)
		return -1;
	node_t *tmp;
	
	new->desc = (desc_t *)heapAlloc(sizeof(desc_t));
        memcpy((void *)new->desc, (void *)desc, sizeof(desc_t));

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




		
		
	

