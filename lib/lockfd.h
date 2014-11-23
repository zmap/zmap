#include <stdio.h>

int lock_fd(int fd);
int unlock_fd(int fd);
int lock_file(FILE *f);
int unlock_file(FILE *f);
