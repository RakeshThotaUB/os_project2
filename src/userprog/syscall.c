#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);

extern bool running;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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

