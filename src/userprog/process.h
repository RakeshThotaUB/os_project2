#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct process_metadata
{
  tid_t process_id;
  bool load_status;
  int exit_status;
  struct semaphore process_load_sema;
  struct semaphore process_exit_sema;
  struct list_elem metadata_elem;
  struct file *executable_file;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
int process_write(int fd, const void *buffer, unsigned size);

#endif /* userprog/process.h */
