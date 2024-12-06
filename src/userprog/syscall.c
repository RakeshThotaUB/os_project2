#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);
static int (*syscall_handlers[20]) (struct intr_frame *); /* Array of syscall functions */

extern bool running;
static bool is_valid_pointer(void * esp, uint8_t argc){
  uint8_t i = 0;
  for (; i < argc; ++i)
  {
    if (get_user(((uint8_t *)esp)+i) == -1){
      return false;
    }
  }
  return true;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_handlers[SYS_EXIT] = &syscall_exit_wrapper;
  syscall_handlers[SYS_WRITE] = &syscall_write_wrapper;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int * p = f->esp;


  int system_call = * p;

	switch (system_call)
	{
		case SYS_HALT:
    {
		shutdown_power_off();
    NOT_REACHED();
    }
		break;

		case SYS_EXIT:
    {
		thread_current()->parent->exit_status = true;
		thread_exit();
    }
		break;

		case SYS_WRITE:
    {
      int fd = *(p + 1), size;
      char *buffer = *(p + 2);
      size = *(p + 3);
      if (fd == 1){
        putbuf(buffer, size);
      }
    }
		break;

		default:
		printf("There are no match for system call %d\n", system_call);
	}
}

static void
kill_program(void)
{
  thread_exit(-1);
}

static void
syscall_handler (struct intr_frame *f)
{

  if (!is_valid_pointer(f->esp, 4)){
    kill_program();
    return;
  }
  int syscall_num = * (int *)f->esp;

  if (syscall_num < 0 || syscall_num >= 20){
    kill_program();
    return;
  }
  if(syscall_handlers[syscall_num](f) == -1){
    kill_program();
    return;
  }
}

static int
syscall_exit_wrapper(struct intr_frame *f)
{
  int status;
  if (is_valid_pointer(f->esp + 4, 4))
    status = *((int*)f->esp+1);
  else
    return -1;
  syscall_exit(status);
  return 0;
}
static int
syscall_write_wrapper(struct  intr_frame *f)
{
  if (!is_valid_pointer(f->esp + 4, 12)){
    return -1;
  }
  int fd = *(int *)(f->esp + 4);
  void *buffer = *(char**)(f->esp + 8);
  unsigned size = *(unsigned *)(f->esp + 12);
  if (!is_valid_pointer(buffer, 1) || !is_valid_pointer(buffer + size,1)){
    return -1;
  }
  int written_size = process_write(fd, buffer, size);
  f->eax = written_size;
  return 0;
}