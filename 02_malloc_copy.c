#include <stdio.h>
#include <stdlib.h>

long globVar1 = 10;
int globVar2 = 20;
char globVar3 = 'a';

void addressPrint(char *str, int *var){
   //printf("Address of %s: %p\n", str, var);
   printf("Address of %s: %lx\n", str, (unsigned long)var);
}

void stackAlloc() {
   long stackVar1 = 10;
   int stackVar2 = 20;
   char stackVar3 = 'a';
   
   addressPrint("LONG stackVar1", &stackVar1);
   addressPrint("INT stackVar2", &stackVar2);
   addressPrint("CHAR stackVar3", &stackVar3);
}

int main() {
   printf("### GLOBAL VARS ###\n");  
   addressPrint("LONG globalVar1", &globVar1);
   addressPrint("INT globalVar2", &globVar2);
   addressPrint("CHAR globalVar3", &globVar3);
      
   printf("\n### STACK VARS ###\n");
   stackAlloc();

   printf("\n### HEAP VARS ###\n");
   long* heapVar1 = (long*) malloc(sizeof(long));
   *heapVar1 = 10;
   int* heapVar2 = (int*) malloc(sizeof(int));
   *heapVar2 = 20;
   char* heapVar3 = (char*) malloc(sizeof(char));
   *heapVar3 = 'a';
   addressPrint("LONG heapVar1", heapVar1);
   addressPrint("INT heapVar2", heapVar2);
   addressPrint("CHAR heapVar3", heapVar3);
}
