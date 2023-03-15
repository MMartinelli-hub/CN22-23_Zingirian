#include <stdio.h>

int main(){
   int a = 1;
   char *p = &a;
   //printf("a = %d, p= %d\n", a, *p);
   if(*p)
      printf("Little Endian\n");
   else
      printf("Big Endian\n");
}
