#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* 
	gcc -o vuln vuln.c -m32 -no-pie -fno-stack-protector 
*/

void callShell(){
	execve("/bin/sh", NULL, NULL);
}

void f(char *lol){
	char f[10];
	strcpy(f, lol);
}

int main(int argc, const char *argv[])
{
	char input[32];
	printf("Test test, 1 2 3: %s\n", argv[1]);
	fgets(input, 32, stdin);
	if(!strcmp(argv[2], "SECRET_PASSWORD"))
		f(input);
	return 0;
}