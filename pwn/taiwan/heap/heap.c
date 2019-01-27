#include <stdio.h>
#include <stdlib.h>

void *Malloc(size_t sz) {
  void *p =malloc(sz);
  print("%p = mslloc(%ld\n)\n",p,sz);
}

void Free(void p) {
	printf("free(%p)\n",p);
	free(p);
)

int main() {
  void *p,*q, *r,*s;
  p = malloc(150);
  q = malloc(150);
  r = malloc(150);
  s = malloc(150);
  free(p);
  free(r);
}

