#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include <string.h>
#include <ctype.h>
#include <devices/shutdown.h>
#include <devices/input.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <kernel/console.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <userprog/process.h>

struct semaphore filesys_sema;

static void syscall_handler (struct intr_frame *);

// Macro is used for fetching the arguments
#define FETCH_ARG(type, esp, offset) ({                  \
    void *argument_pointer = (void *)((esp) + (offset) * 4);      \
    check_ptr(argument_pointer);                                  \
    (type)(*((type *)argument_pointer));                          \
})

static void
syscall_handler (struct intr_frame *f) 
{
  int args[3];
  check_ptr (f->esp);

  void *esp = f->esp;
  int syscall_num = FETCH_ARG(int, esp, 0);
  struct thread *cur = thread_current ();

  switch (syscall_num)
  {
   case SYS_HALT:
      syscall_halt ();
      break;

  case SYS_EXIT: {
      int exit_status = FETCH_ARG(int, esp, 1);
      exit(exit_status);
      break;
  }
        

   case SYS_EXEC: {
      const char *command_line = FETCH_ARG(const char *, esp, 1);
      f->eax = exec((const char *)pagedir_get_page(cur->pagedir, command_line));
      break;
  }

  case SYS_WAIT: {
      pid_t pid = FETCH_ARG(pid_t, esp, 1);
      f->eax = syscall_wait(pid);
      break;
  }

  case SYS_WRITE: {
      int fd = FETCH_ARG(int, esp, 1);
      const void *buffer = FETCH_ARG(const void *, esp, 2);
      unsigned size = FETCH_ARG(unsigned, esp, 3);
      buffer = pagedir_get_page(cur->pagedir, buffer);
      f->eax = syscall_write(fd, buffer, size);
      break;
  }

  case SYS_READ: {
      int fd = FETCH_ARG(int, esp, 1);
      void *buffer = FETCH_ARG(void *, esp, 2);
      unsigned size = FETCH_ARG(unsigned, esp, 3);
      f->eax = syscall_read(fd, buffer, size);
      break;
  }

   case SYS_CREATE: {
      const char *file_name = FETCH_ARG(const char *, esp, 1);
      unsigned size = FETCH_ARG(unsigned, esp, 2);
      file_name = (const char *)pagedir_get_page(cur->pagedir, file_name);
      f->eax = create(file_name, size);
      break;
  }

  case SYS_REMOVE: {
      const char *file_name = FETCH_ARG(const char *, esp, 1);
      file_name = (const char *)pagedir_get_page(cur->pagedir, file_name);
      sema_down(&filesys_sema);
      f->eax = filesys_remove(file_name);
      sema_up(&filesys_sema);
      break;
  }

  case SYS_OPEN: {
      const char *file_name = FETCH_ARG(const char *, esp, 1);
      f->eax = open(file_name);
      break;
  }

  case SYS_FILESIZE: {
      int fd = FETCH_ARG(int, esp, 1);
      f->eax = filesize(fd);
      break;
  }

  case SYS_CLOSE: {
      int fd = FETCH_ARG(int, esp, 1);
      close(fd);
      break;
  }

  case SYS_TELL: {
      int fd = FETCH_ARG(int, esp, 1);
      f->eax = tell(fd);
      break;
  }

  case SYS_SEEK: {
      int fd = FETCH_ARG(int, esp, 1);
      unsigned position = FETCH_ARG(unsigned, esp, 2);
      seek(fd, position);
      break;
  }
  default: {
      exit(-1);
  }
}
}

void
get_arguments (int *esp, int *args, int count)
{
  for (int i = 0; i < count; i++)
  {
    int *next = ((esp + i) + 1);
    check_ptr (next);
    args[i] = *next;
  }
}

void 
check_ptr(void *ptr) {
    if (ptr == NULL || !is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
        exit(-1);
    }
}

void 
syscall_halt(void) {
    shutdown();
}

void
exit (int status)
{
  struct thread *cur = thread_current ();
  cur->proc_metadata->exit_status = status;
  sema_up (&cur->proc_metadata->process_exit_sema);
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

bool
create (const char *file_name, unsigned size)
{
  if (file_name == NULL) exit (-1);    
  sema_down (&filesys_sema);
  bool succ = filesys_create (file_name, size);
  sema_up (&filesys_sema);
  return succ;
}

int
open (const char *file)
{
  
  check_ptr ((void *)file);
  if (file == NULL || strcmp(file, "") == 0) return -1;

  sema_down (&filesys_sema);
  struct file *opened_file = filesys_open (file); 
  sema_up (&filesys_sema);

  if (opened_file == NULL) return -1;

  struct thread *cur = thread_current ();
  if (file_get_inode (opened_file) == file_get_inode(cur->proc_metadata->executable_file))
      file_deny_write (opened_file);

  int i = 2;
  while (i < MAX_FD) {
      if (cur->fd[i] == NULL) {
          cur->fd[i] = opened_file;
          return i;
      }
      i++;
  }
  return -1;
}  


static int
read_from_stdin(char *buffer, unsigned size)
{
  unsigned val = 0;
  while (val < size) // Leaving space for the null terminator 
  {
    char input = input_getc();
    buffer[val++] = input;
    if (input == '\n') break;
  }
  return (int)val;  // Returning the number of bytes that are read
}

static 
int read_from_file(int file_descriptor, char *buffer, unsigned size)
{
  struct thread *cur = thread_current();
  struct file *fd_file = cur->fd[file_descriptor];
   if (fd_file == NULL) return -1;  // Invalid fd
  // Deny the writes if it is exec file
  if (file_get_inode(fd_file) == file_get_inode(cur->proc_metadata->executable_file))
  {
    file_deny_write(fd_file);
  }
  return file_read(fd_file, buffer, size);
}

int
syscall_read (int fd, void *buffer, unsigned size)
{
  struct thread *cur = thread_current ();
  char *buff = (char *)buffer;
  check_ptr (buff);
  int return_value;
  if (fd == 1 || fd < 0 || fd >= 128)
    exit (-1);
  if (fd == 0) return read_from_stdin(buff, size);
  else  
  {
    sema_down(&filesys_sema);
    return_value = read_from_file(fd, buff, size);
    sema_up(&filesys_sema);
  }
  return return_value;
}

int
syscall_write (int file_desc, const void *_buffer, unsigned size)
{
  char *buffer = (char *)_buffer;
  struct thread *cur = thread_current ();
  struct file *file_to_write;

  if (buffer == NULL)
    exit (-1);
  int retval;
  if (file_desc < 1 || file_desc > 128)
    return -1;
  if (file_desc == 1) {
    putbuf (buffer, size);
    retval = size;
  }
  else
  {
    sema_down (&filesys_sema);
    file_to_write = cur->fd[file_desc];
    if (file_to_write != NULL) {
    	retval = file_write (file_to_write, buffer, size);
    	cur->fd[file_desc] = file_to_write;
        file_allow_write (file_to_write);
    }
    else retval = -1;
    sema_up (&filesys_sema);
  }
  return retval;
}


void
close (int file_descriptor)
{
  struct thread *cur = thread_current ();
  if (file_descriptor >= 128 || file_descriptor < 2) 
    return;
  sema_down (&filesys_sema);
  if (cur->fd[file_descriptor] != NULL) {
    file_close (cur->fd[file_descriptor]);
    cur->fd[file_descriptor] = NULL;
  }
  sema_up (&filesys_sema);
}

int
filesize (int file_descriptor)
{
  struct thread *cur = thread_current ();
  struct file *file;
  file = cur -> fd[file_descriptor];
  if (file == NULL || file_descriptor < 2 || file_descriptor >= 128)
    exit (-1);
  return file_length (file);
}

unsigned
tell (int file_descriptor)
{
  struct thread *cur = thread_current ();
  struct file *file;
  file = cur -> fd[file_descriptor];
  if (file == NULL || file_descriptor < 2 || file_descriptor >= 128){
    exit (-1);
  }
  return file_tell (file);
} 

void
seek (int fd, unsigned location)
{
  struct thread *cur = thread_current ();
  struct file *file;
  file = cur -> fd[fd];
  if (file == NULL || fd < 2 || fd >= 128){
    exit (-1);
  }
  file_seek (file, location);
}

pid_t
exec (const char *file)
{
  if (file == NULL) exit (-1);
  tid_t child_tid = process_execute (file);
  return (pid_t)child_tid;
}

int
syscall_wait (pid_t pid)
{
  return process_wait((tid_t)pid);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  sema_init(&filesys_sema, 1);
}