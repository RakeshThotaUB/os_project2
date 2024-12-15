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

// Macro is used for fetching the arguments from the stack
#define FETCHING_ARGS(type, esp, offset) ({                  \
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
  int syscall_num = FETCHING_ARGS(int, esp, 0);  // Get the syscall num
  struct thread *cur = thread_current ();

  switch (syscall_num)
  {
   case SYS_HALT:
      syscall_halt ();  // Shutdown 
      break;

  case SYS_EXIT: {
      int exit_status;
      exit_status = FETCHING_ARGS(int, esp, 1);
      exit(exit_status);  // Exit the current process
      break;
  }
        
   case SYS_EXEC: {
      const char *command_line = FETCHING_ARGS(const char *, esp, 1);
      check_str(command_line);
      f->eax = exec((const char *)pagedir_get_page(cur->pagedir, command_line)); // Executing the program
      break;
  }

  case SYS_WAIT: {
      pid_t pid = FETCHING_ARGS(pid_t, esp, 1);
      f->eax = syscall_wait(pid);  // Wait for the child process for finish
      break;
  }

  case SYS_WRITE: {
      int fd = FETCHING_ARGS(int, esp, 1);
      const void *buffer = FETCHING_ARGS(const void *, esp, 2);
      unsigned size = FETCHING_ARGS(unsigned, esp, 3);
      buffer = pagedir_get_page(cur->pagedir, buffer);
      f->eax = syscall_write(fd, buffer, size); // Write to a file/console
      break;
  }

  case SYS_READ: {
      int fd = FETCHING_ARGS(int, esp, 1);
      void *buffer = FETCHING_ARGS(void *, esp, 2);
      unsigned size = FETCHING_ARGS(unsigned, esp, 3);
      f->eax = syscall_read(fd, buffer, size);        // Read from the file/input
      break;
  }

   case SYS_CREATE: {
      const char *file_name = FETCHING_ARGS(const char *, esp, 1);
      unsigned size = FETCHING_ARGS(unsigned, esp, 2);
      file_name = (const char *)pagedir_get_page(cur->pagedir, file_name);
      f->eax = create(file_name, size);           // Create file
      break;
  }

  case SYS_REMOVE: {
      const char *file_name = FETCHING_ARGS(const char *, esp, 1);
      file_name = (const char *)pagedir_get_page(cur->pagedir, file_name);
      sema_down(&filesys_sema);
      f->eax = filesys_remove(file_name);
      sema_up(&filesys_sema);
      break;
  }

  case SYS_OPEN: {
      const char *file_name = FETCHING_ARGS(const char *, esp, 1);
      f->eax = open(file_name);
      break;
  }

  case SYS_FILESIZE: {
      int fd = FETCHING_ARGS(int, esp, 1);
      f->eax = syscall_filesize(fd);          // Get size of a file
      break;
  }

  case SYS_CLOSE: {
      int fd = FETCHING_ARGS(int, esp, 1);
      close(fd);
      break;
  }

  case SYS_TELL: {
      int fd = FETCHING_ARGS(int, esp, 1);
      f->eax = tell(fd);                         // Get current position in the file
      break;
  }

  case SYS_SEEK: {
      int fd = FETCHING_ARGS(int, esp, 1);
      unsigned position = FETCHING_ARGS(unsigned, esp, 2);
      seek(fd, position);                       // Change current position in the file
      break;
  }
  default: {
      exit(-1);
  }
}
}

// Checking if the user pointer is valid or not
void 
check_ptr(void *uaddr) {
    if (uaddr == NULL || !is_user_vaddr(uaddr) || pagedir_get_page(thread_current()->pagedir, uaddr) == NULL) {
        exit(-1);
    }
}

void 
check_str(const char *string) {
    if (string == NULL)  exit(-1); 
    char *ptr = string;
    for (; is_user_vaddr(ptr); ptr++) {
        if (pagedir_get_page(thread_current()->pagedir, (void *)ptr) == NULL) exit(-1); 
        if (*ptr == '\0') return; 
    }
    exit(-1);
}

void 
syscall_halt(void) {
    shutdown();
}

void
exit (int status)
{
  struct thread *current_thread = thread_current ();
  if (current_thread->proc_metadata != NULL) {
        current_thread->proc_metadata->exit_status = status;
        sema_up(&current_thread->proc_metadata->process_exit_sema);
    }
  printf ("%s: exit(%d)\n", current_thread->name, status);
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
  struct thread *current_thread = thread_current ();
  struct inode *opened_file_inode = file_get_inode(opened_file);
  struct inode *exec_file_inode = file_get_inode(current_thread->proc_metadata->executable_file);
  if (opened_file_inode == exec_file_inode) {
      file_deny_write(opened_file);
  }

  int i = 2;
  while (i < MAX_FD) {
      if (current_thread->fd[i] == NULL) {
          current_thread->fd[i] = opened_file;
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
  while (val < size) 
  {
    char input = input_getc();
    buffer[val++] = input;
    if (input == '\n') break;
  }
  return (int)val;  
}

static 
int read_from_file(int file_descriptor, char *buff, unsigned size)
{
  struct thread *current_thread = thread_current();
  struct file *file_descriptor_file = current_thread->fd[file_descriptor];
   if (file_descriptor_file == NULL) return -1;  // Invalid fd
  // Deny the writes if it is exec file
  struct inode *opened_file_inode = file_get_inode(file_descriptor_file);
  struct inode *exec_file_inode = file_get_inode(current_thread->proc_metadata->executable_file);
  if (opened_file_inode == exec_file_inode) {
      file_deny_write(file_descriptor_file);
  }

  return file_read(file_descriptor_file, buff, size);
}

int
syscall_read (int fd, void *buffer, unsigned size)
{
  struct thread *current_thread = thread_current ();
  char *buff = (char *)buffer;
  check_ptr (buff);
  int return_value;
  
  if (fd == 0) return read_from_stdin(buff, size);
  if (fd == 1 || fd < 0 || fd >= 128) {
    exit (-1);
  }
  else  
  {
    sema_down(&filesys_sema);
    return_value = read_from_file(fd, buff, size);
    sema_up(&filesys_sema);
  }
  return return_value;
}

static int write_to_stdout(const char *buff, unsigned size)
{
  putbuf(buff, size);  
  return size;           
}

static int write_to_file(int file_descriptor, const char *buff, unsigned size, int return_val)
{
  struct thread *current_thread = thread_current();
  struct file *target_file;
  int return_value = return_val; 
  target_file = current_thread->fd[file_descriptor];  
  if (target_file == NULL){
    return -1; 
  } 
  return_value = file_write(target_file, buff, size); 
  current_thread->fd[file_descriptor] = target_file; 
  file_allow_write(target_file);  
  return return_value;  
}

int
syscall_write(int file_descriptor, const void *buffer, unsigned size)
{
  const char *buff = (const char *)buffer;  
  if (file_descriptor < 1 || file_descriptor >= 128)
    return -1;
  if (buff == NULL)
    exit(-1);
  int return_val;  
  if (file_descriptor == 1)  
  {
    return_val = write_to_stdout(buff, size);
  }
  else  
  {
    sema_down(&filesys_sema);  
    return_val = write_to_file(file_descriptor, buff, size, return_val);
    sema_up(&filesys_sema);
  }
  return return_val;  
}

void
close (int file_descriptor)
{
  if (file_descriptor >= 128 || file_descriptor < 2) {
    return;
  }
  sema_down (&filesys_sema);
  struct thread *current_thread = thread_current();
  if (current_thread->fd[file_descriptor] != NULL) {
    file_close (current_thread->fd[file_descriptor]);
    current_thread->fd[file_descriptor] = NULL;
  }
  sema_up (&filesys_sema);
}

int
syscall_filesize (int file_descriptor)
{
  struct thread *current_thread = thread_current ();
  struct file *file;
  file = current_thread -> fd[file_descriptor];
  if (file == NULL){
    exit (-1);
  }
  else if (file_descriptor < 2){
    exit (-1);
  }
  else if (file_descriptor >= 128){
    exit (-1);
  }
  return file_length (file);
}

unsigned
tell (int file_descriptor)
{
  struct thread *current_thread = thread_current ();
  struct file *file;
  file = current_thread -> fd[file_descriptor];
  if (file == NULL){
    exit (-1);
  }
  else if (file_descriptor < 2){
    exit (-1);
  }
  else if (file_descriptor >= 128){
    exit (-1);
  }
  return file_tell (file);
} 

void
seek (int file_descriptor, unsigned loc)
{
  struct thread *current_thread = thread_current ();
  struct file *file;
  file = current_thread -> fd[file_descriptor];
  if (file == NULL){
    exit (-1);
  }
  else if (file_descriptor < 2){
    exit (-1);
  }
  else if (file_descriptor >= 128){
    exit (-1);
  }
  file_seek (file, loc);
}

pid_t
exec (const char *file)
{
  if (file == NULL) exit (-1);
  tid_t child_process_id = process_execute (file);

  return (pid_t)child_process_id;
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