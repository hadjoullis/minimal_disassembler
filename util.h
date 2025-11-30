#ifndef _H_UTIL
#define _H_UTIL

#include <elf.h>

#define DIE(...)                                                               \
  do {                                                                         \
    fprintf(stderr, __VA_ARGS__);                                              \
    fputc('\n', stderr);                                                       \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

#define BUF_LEN 256
// sizeof 2 bytes + space + null
#define TEMP_LEN 4

typedef struct {
  Elf64_Addr addr;
  char *func_name;
} function_t;
#endif
