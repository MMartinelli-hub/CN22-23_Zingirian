#include <stdio.h>
#include <stdlib.h>

int a;

int fact(int n){
   int *p = (int *)malloc(sizeof(int));
   printf("Static: %lx\tStack: %lx\tHeap: %lx\n", (unsigned long)&a, (unsigned long)&n, (unsigned long)p);
   if(n<=1)
      return n;
   return n*fact(n-1);
}

int main(int argc, char **argv){
   if(argc != 2){
      printf("Usage %s <num>\n", argv[0]);
      return 0;
   }
   int n = atoi(argv[1]);
   printf("The factorial of %d is %d\n", n, fact(n));
}
