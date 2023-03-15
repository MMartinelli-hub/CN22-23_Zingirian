#include <stdio.h>
#include <stdlib.h>

int globVar1 = 10;
int globVar2 = 20;
int globVar3 = 30;

void addressPrint(char *str, int *var){
   //printf("Address of %s: %p\n", str, var);
   printf("Address of %s: %lx\n", str, (unsigned long)var);
}

void stackAlloc() {
   int stackVar1 = 10;
   int stackVar2 = 20;
   int stackVar3 = 30;
   
   addressPrint("stackVar1", &stackVar1);
   addressPrint("stackVar2", &stackVar2);
   addressPrint("stackVar3", &stackVar3);
}

int main() {
   printf("### GLOBAL VARS ###\n");  
   addressPrint("globalVar1", &globVar1);
   addressPrint("globalVar2", &globVar2);
   addressPrint("globalVar3", &globVar3);
      
   printf("\n### STACK VARS ###\n");
   stackAlloc();

   printf("\n### HEAP VARS ###\n");
   int* heapVar1 = (int*) malloc(sizeof(int));
   *heapVar1 = 10;
   int* heapVar2 = (int*) malloc(sizeof(int));
   *heapVar2 = 20;
   int* heapVar3 = (int*) malloc(sizeof(int));
   *heapVar3 = 30;
   addressPrint("heapVar1", heapVar1);
   addressPrint("heapVar2", heapVar2);
   addressPrint("heapVar3", heapVar3);
}
