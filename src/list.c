/*
 * Copyright (c) 2015, Ryan O'Neill
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * ECFS (Extended core file snapshot) utility (C) 2014 Ryan O'Neill
 * http://www.bitlackeys.org/#research
 * elfmaster@zoho.com
 */

#include "../include/ecfs.h"

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




		
		
	

