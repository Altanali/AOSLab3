  #include <stdlib.h>
  #include <assert.h>

  #define SIZE 64
  
  #define MAGIC 0xCC // (can be any value you want)

  int main() {
    unsigned char* mem = malloc(SIZE);
    for(int i = 0; i < SIZE; i++)
      assert(mem[i] == MAGIC);
  }