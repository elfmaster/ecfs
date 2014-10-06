/*
 * ECFS (Extended core file snapshot) utility (C) 2014 Ryan O'Neill
 * http://www.bitlackeys.org/#research
 * elfmaster@zoho.com
 */


#include "vv.h"

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

/*
int main(void)
{
	list_t *list;
	node_t *current;
	list->head = NULL;
	list->tail = NULL;

	insert_front(&list, 1);
	insert_front(&list, 2);
	insert_front(&list, 3);
	insert_front(&list, 4);
	
	for (current = list->tail; current != NULL; current = current->prev)
		printf("%d\n", current->item);
	
	
	
}
*/
			
		



		
		
	

