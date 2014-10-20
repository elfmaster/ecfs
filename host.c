#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char array[500];

int main(void)
{
	char *p = malloc(50);
	int i;

	for (i = 0; i < 500; i++)
		array[i] = rand() % 500;
	printf("hi\n");
	fork();
	pause();
}

