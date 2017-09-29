---
layout: post
date:   2017-06-26 15:12:01 -0600
categories: writeups
description: "Bomb challenge writeup from the Modern Binary Exploitation course."
title:  "Basic Reverse Engineering (writeup) - Part 0x01"
author: "Iliya Dafchev"
---

# Introduction

I've started a course on [Modern Binary Exploitation](http://security.cs.rpi.edu/courses/binexp-spring2015/) and throughout this course there are challenges and labs with which to practice exploitation techniques. It starts with an introduction to reverse engineering and I've decided to write about how I solved the challenges and take notes of the things I learned.

This (as you can see) is the second post and it will focus on the bombs challenges from the "Extended Reverse Engineering" class. It came out too long, so this post is going to be about only the bomb executable. The cmubomb and crackme0x04_win.exe will be in separate posts.

### If you plan to take the course I highly encourage you not to read any further and try to solve the challenges yourself. You'll learn much more that way.

This time I'll make use of gdb(pwndbg) and IDA. Also for some of the challenges you don't need to look at every assembly instruction but just looking at the function calls and byte/string comparisons you can immediately understand what input is expected without reversing the whole thing.

## bomb

After starting the bomb executable, we're presented with four options - YELLOW, GREEN, BLUE and RED, corresponding to the wires that we need to cut to deactivate the bomb. When we choose an option we are asked about a password. Entering the right password cuts the wire and entering the wrong password blows the bomb. Our mission is to reverse the algorithms and find the passwords for each wire and deactivate the bomb.

Let's start with Yellow.

## Yellow

![bomb_yellow_1](/images/basic_reverse_engineering/bomb_yellow_1.png)

First I list the functions that are present in the executable. I assume that the function *yellow*{: style="color: LightGreen"} handles the logic for the yellow option and disassembling yellow immediately shows something interesting.

```
$ gdb
pwndbg> file bomb
Reading symbols from bomb...done.

pwndbg> info functions 
All defined functions:

Non-debugging symbols:

...............
output omitted
...............

0x08048a4c  menu
0x08048fb4  kaboom
0x08048fc8  libc_start_main
0x080491cf  disarm_handler
0x080494ca  main
0x080496e8  yellow_preflight
0x08049719  yellow
0x080497a4  red_preflight
0x08049831  red
0x080498cc  postred
0x080498d4  green_preflight
0x08049904  green
0x080499c0  blue_preflight
0x080499f1  blue

...............
output omitted
...............

pwndbg> disass yellow
Dump of assembler code for function yellow:
```

```nasm
   0x08049719 <+0>: push   ebp
   0x0804971a <+1>: mov    ebp,esp
   0x0804971c <+3>: sub    esp,0x8
   0x0804971f <+6>: call   0x80496e8 <yellow_preflight>
   0x08049724 <+11>:  movzx  eax,BYTE PTR ds:0x804c24c
   ; 0x38 = ascii 8
   0x0804972b <+18>:  cmp    al,0x38
   0x0804972d <+20>:  jne    0x804977c <yellow+99>
   0x0804972f <+22>:  movzx  eax,BYTE PTR ds:0x804c24d
   ; 0x34 = ascii 4
   0x08049736 <+29>:  cmp    al,0x34
   0x08049738 <+31>:  jne    0x804977c <yellow+99>
   0x0804973a <+33>:  movzx  eax,BYTE PTR ds:0x804c24e
   ; 0x33 = ascii 3
   0x08049741 <+40>:  cmp    al,0x33
   0x08049743 <+42>:  jne    0x804977c <yellow+99>
   0x08049745 <+44>:  movzx  eax,BYTE PTR ds:0x804c24f
   ; 0x37 = ascii 7
   0x0804974c <+51>:  cmp    al,0x37
   0x0804974e <+53>:  jne    0x804977c <yellow+99>
   0x08049750 <+55>:  movzx  eax,BYTE PTR ds:0x804c250
   ; 0x31= ascii 1
   0x08049757 <+62>:  cmp    al,0x31
   0x08049759 <+64>:  jne    0x804977c <yellow+99>
   0x0804975b <+66>:  movzx  eax,BYTE PTR ds:0x804c251
   ; 0x30 = ascii 0
   0x08049762 <+73>:  cmp    al,0x30
   0x08049764 <+75>:  jne    0x804977c <yellow+99>
   0x08049766 <+77>:  movzx  eax,BYTE PTR ds:0x804c252
   ; 0x36 = ascii 6
   0x0804976d <+84>:  cmp    al,0x36
   0x0804976f <+86>:  jne    0x804977c <yellow+99>
   0x08049771 <+88>:  movzx  eax,BYTE PTR ds:0x804c253
   ; 0x35 = ascii 5
   0x08049778 <+95>:  cmp    al,0x35
   0x0804977a <+97>:  je     0x804978b <yellow+114>
   0x0804977c <+99>:  mov    eax,ds:0x804c124
   0x08049781 <+104>: shl    eax,0xa
   0x08049784 <+107>: mov    ds:0x804c124,eax
   0x08049789 <+112>: jmp    0x80497a1 <yellow+136>
   0x0804978b <+114>: mov    DWORD PTR [esp],0x804a1f4
   0x08049792 <+121>: call   0x80487b4 <puts@plt>
   0x08049797 <+126>: mov    DWORD PTR ds:0x804c124,0x0
   0x080497a1 <+136>: leave  
   0x080497a2 <+137>: ret    

   ; password is 84371065
```
There is a comparison of each consecutive byte from *ds:0x804c24c*{: style="color: LightSalmon"} to *ds:0x804c253*{: style="color: LightSalmon"} with the bytes *0x38*{: style="color: LightSalmon"}, *0x34*{: style="color: LightSalmon"}, *0x33*{: style="color: LightSalmon"}, *0x37*{: style="color: LightSalmon"}, *0x31*{: style="color: LightSalmon"}, *0x30*{: style="color: LightSalmon"}, *0x36*{: style="color: LightSalmon"}, *0x35*{: style="color: LightSalmon"} respectively. The ascii representation of those bytes is *84371065*{: style="color: LightSalmon"}.

I bet that our input is stored at *ds:0x804c24c*{: style="color: LightSalmon"} and is checked against *84371065*{: style="color: LightSalmon"}.

Disassembling *yellow_preflight*{: style="color: LightGreen"} also validates my suspicion that our input is stored at *ds:0x804c24c*{: style="color: LightSalmon"}. I guess all *preflight*{: style="color: LightGreen"} functions just read our input.

And to try the password:
![bomb_yellow_2](/images/basic_reverse_engineering/bomb_yellow_2.png)

It worked! We cut the yellow wire.

## Green

Disassembling green it's easy to notice where our input is stored and that there is a string comparison with a string at address 0x804a2c0.

```nasm
pwndbg> disass green
Dump of assembler code for function green:
   0x08049904 <+0>: push   ebp
   0x08049905 <+1>: mov    ebp,esp
   0x08049907 <+3>: sub    esp,0x38
   0x0804990a <+6>: mov    eax,gs:0x14
   0x08049910 <+12>:  mov    DWORD PTR [ebp-0x4],eax
   0x08049913 <+15>:  xor    eax,eax
   0x08049915 <+17>:  mov    DWORD PTR [ebp-0x8],0x1
   ; [ebp-0x14] = user_input
   0x0804991c <+24>:  lea    eax,[ebp-0x14]
   0x0804991f <+27>:  mov    DWORD PTR [esp],eax
   0x08049922 <+30>:  call   0x80498d4 <green_preflight>
   0x08049927 <+35>:  mov    DWORD PTR [esp+0x8],0x8
   0x0804992f <+43>:  lea    eax,[ebp-0x14]
   0x08049932 <+46>:  mov    DWORD PTR [esp+0x4],eax
   0x08049936 <+50>:  mov    DWORD PTR [esp],0x804a2c0
   ; strncmp(0x804a2c0, user_input, 8)
   0x0804993d <+57>:  call   0x80487d4 <strncmp@plt>
   0x08049942 <+62>:  test   eax,eax
   ; to go to 'UNLOCK PASSWORD ACCEPTED' strings should be equal
   0x08049944 <+64>:  jne    0x804998e <green+138>
   0x08049946 <+66>:  mov    DWORD PTR [esp],0x804a2fc
   ; puts('UNLOCK PASSWORD ACCEPTED')
   0x0804994d <+73>:  call   0x80487b4 <puts@plt>
   0x08049952 <+78>:  mov    eax,DWORD PTR [ebp-0x8]
   0x08049955 <+81>:  and    eax,0x1
   0x08049958 <+84>:  test   eax,eax
   0x0804995a <+86>:  sete   al
   0x0804995d <+89>:  movzx  eax,al
   0x08049960 <+92>:  mov    DWORD PTR [ebp-0x8],eax
   0x08049963 <+95>:  mov    DWORD PTR [esp],0x7a120
   0x0804996a <+102>: call   0x8048724 <usleep@plt>
   0x0804996f <+107>: mov    DWORD PTR [esp],0x804a33c
   ; puts('ACTION OVERRIDEN....')
   0x08049976 <+114>: call   0x80487b4 <puts@plt>
   0x0804997b <+119>: mov    eax,DWORD PTR [ebp-0x8]
   0x0804997e <+122>: and    eax,0x1
   0x08049981 <+125>: test   eax,eax
   0x08049983 <+127>: sete   al
   0x08049986 <+130>: movzx  eax,al
   0x08049989 <+133>: mov    DWORD PTR [ebp-0x8],eax
   0x0804998c <+136>: jmp    0x804999a <green+150>
   0x0804998e <+138>: mov    eax,ds:0x804c12c
   0x08049993 <+143>: add    eax,eax
   0x08049995 <+145>: mov    ds:0x804c12c,eax
   0x0804999a <+150>: mov    eax,DWORD PTR [ebp-0x8]
   0x0804999d <+153>: test   eax,eax
   0x0804999f <+155>: jne    0x80499ad <green+169>
   0x080499a1 <+157>: mov    eax,ds:0x804c12c
   0x080499a6 <+162>: sar    eax,1
   0x080499a8 <+164>: mov    ds:0x804c12c,eax
   0x080499ad <+169>: mov    eax,DWORD PTR [ebp-0x4]
   0x080499b0 <+172>: xor    eax,DWORD PTR gs:0x14
   0x080499b7 <+179>: je     0x80499be <green+186>
   0x080499b9 <+181>: call   0x8048784 <__stack_chk_fail@plt>
   0x080499be <+186>: leave  
   0x080499bf <+187>: ret   
```

And as you can see the address 0x804a2c0 points to the string "dcaotdae".
```
pwndbg> x/s 0x804a2c0
0x804a2c0 <password>: "dcaotdae"
```

![bomb_green_1](/images/basic_reverse_engineering/bomb_green_1.png)

## Blue

```nasm
pwndbg> disass blue_preflight 
Dump of assembler code for function blue_preflight:
   0x080499c0 <+0>: push   ebp
   0x080499c1 <+1>: mov    ebp,esp
   0x080499c3 <+3>: sub    esp,0x18
   0x080499c6 <+6>: mov    DWORD PTR [esp],0x804a388
   0x080499cd <+13>:  call   0x8048744 <printf@plt>
   0x080499d2 <+18>:  mov    eax,ds:0x804c220
   0x080499d7 <+23>:  mov    DWORD PTR [esp+0x8],eax
   0x080499db <+27>:  mov    DWORD PTR [esp+0x4],0x10
   ; user_input is saved at 0x804c24c; max of 16 characters
   0x080499e3 <+35>:  mov    DWORD PTR [esp],0x804c24c
   0x080499ea <+42>:  call   0x8048704 <fgets@plt>
   0x080499ef <+47>:  leave  
   0x080499f0 <+48>:  ret  

pwndbg> disass blue
Dump of assembler code for function blue:
   0x080499f1 <+0>: push   ebp
   0x080499f2 <+1>: mov    ebp,esp
   0x080499f4 <+3>: sub    esp,0x18
   0x080499f7 <+6>: call   0x80499c0 <blue_preflight>
   ; [ebp-0x4] =: 0x804c160 
   0x080499fc <+11>:  mov    DWORD PTR [ebp-0x4],0x804c160
   ....
```
Hmm... Let's see what's at address 0x804c160

```
pwndbg> x/x 0x804c160
0x804c160 <graph>:	0x0804c19c
```
It's a variable called graph and it appears to hold value that looks like an address. Let's check if it poinsts to anywhere interesting.

```
pwndbg> x/x 0x0804c19c
0x804c19c <graph+60>:	0x0804c1cc
```
Points another address that belongs to the same variable and holds another address. I guess it's going to be the same for this one.

```
pwndbg> x/x 0x0804c1cc
0x804c1cc <graph+108>:	0x0804c1f0
```

Yep... Ok, let's continue analysing the disassembly.

```nasm   
pwndbg> disass blue
Dump of assembler code for function blue:
   0x080499f1 <+0>: push   ebp
   0x080499f2 <+1>: mov    ebp,esp
   0x080499f4 <+3>: sub    esp,0x18
   0x080499f7 <+6>: call   0x80499c0 <blue_preflight>
   ; [ebp-0x4] =: 0x804c160 
   ; 0x804c160 is address of the graph variable
   0x080499fc <+11>:  mov    DWORD PTR [ebp-0x4],0x804c160
   ; eax := 0x804c160
   0x08049a03 <+18>:  mov    eax,DWORD PTR [ebp-0x4]
   ; eax := the value at [0x804c160 + 0x4] 
   0x08049a06 <+21>:  mov    eax,DWORD PTR [eax+0x4]
   ; [ebp-0x8] is var1
   ; var1 := the value at [0x804c160 + 0x4] 
   0x08049a09 <+24>:  mov    DWORD PTR [ebp-0x8],eax
```

And now to see what's at address 0x804c160 + 0x4 :

```
pwndbg> x/x 0x804c160 + 0x4
0x804c164 <graph+4>:	0x47bbfa96
```
We're at the same variable, but at this address it doen't hold a valid address as a value. I'm going to check several consecutive values.

```
0x804c160 <graph>:	0x0804c19c ;valid address
pwndbg> x/x 0x804c160 + 4
0x804c164 <graph+4>:	0x47bbfa96 ; some value
pwndbg> x/x 0x804c160 + 8
0x804c168 <graph+8>:	0x0804c178 ; valid address
pwndbg> x/x 0x804c160 + 12
0x804c16c <graph+12>:	0x0804c214 ; valid address
pwndbg> x/x 0x804c160 + 16 
0x804c170 <graph+16>:	0x50171a6e ; some value
pwndbg> x/x 0x804c160 + 20
0x804c174 <graph+20>:	0x0804c1b4 ; valid address
pwndbg> x/x 0x804c160 + 24
0x804c178 <graph+24>:	0x0804c1d8 ; valid address
pwndbg> x/x 0x804c160 + 28
0x804c17c <graph+28>:	0x23daf3f1 ; some value
pwndbg> x/x 0x804c160 + 32
0x804c180 <graph+32>:	0x0804c1a8 ; valid address
pwndbg> x/x 0x804c160 + 36
0x804c184 <graph+36>:	0x0804c19c ; valid address
pwndbg> x/x 0x804c160 + 40
0x804c188 <graph+40>:	0x634284d3 ; some value
pwndbg> x/x 0x804c160 + 44
0x804c18c <graph+44>:	0x0804c1c0 ; valid address
```

And a pattern emerges. For now I'll continue analysing the disassembly.

```nasm
pwndbg> disass blue
Dump of assembler code for function blue:
   0x080499f1 <+0>: push   ebp
   0x080499f2 <+1>: mov    ebp,esp
   0x080499f4 <+3>: sub    esp,0x18
   0x080499f7 <+6>: call   0x80499c0 <blue_preflight>
   ; [ebp-0x4] =: 0x804c160 
   ; 0x804c160 is address of the graph variable
   0x080499fc <+11>:  mov    DWORD PTR [ebp-0x4],0x804c160
   ; eax := 0x804c160
   0x08049a03 <+18>:  mov    eax,DWORD PTR [ebp-0x4]
   ; eax := the value at [0x804c160 + 0x4] 
   0x08049a06 <+21>:  mov    eax,DWORD PTR [eax+0x4]
   ; [ebp-0x8] is var1
   ; var1 := some the value at [0x804c160 + 0x4] that is not a valid address
   0x08049a09 <+24>:  mov    DWORD PTR [ebp-0x8],eax
   ; [ebp-0xc] is initialized to 0.
   ; Now look at address 0x08049a80 <+143>. 1 is added to it
   ; and if [ebp-0xc] is <= 14 execution returns to 0x8049a15
   ; I'm pretty sure  [ebp-0xc] is an iterator for a loop
   ; [ebp-0xc] is i := 0
   0x08049a0c <+27>:  mov    DWORD PTR [ebp-0xc],0x0
   ; jump to the check if i<= 14. If so return to the 
   ; next instruction at 0x08049a15
   0x08049a13 <+34>:  jmp    0x8049a84 <blue+147>
   ; [ebp-0x10] is initialized to zero
   ; Later in the disassembly you can see that it only gets
   ; assigned 1 or 0. No other operations with it.
   ; I think it's some kind of flag that tells if something happpened or not. 
   ; [ebp-0x10] is flag := 0
   0x08049a15 <+36>:  mov    DWORD PTR [ebp-0x10],0x0
   0x08049a1c <+43>:  mov    eax,DWORD PTR [ebp-0xc]
   ; if you remember 0x804c24c is where our input is stored.
   ; and eax holds the iterator
   ; eax := [i + &input] = user_input[i]
   0x08049a1f <+46>:  movzx  eax,BYTE PTR [eax+0x804c24c]
   0x08049a26 <+53>:  movsx  eax,al
   ; [ebp-0x14] := user_input[i]
   0x08049a29 <+56>:  mov    DWORD PTR [ebp-0x14],eax
   ; 0x4c = ascii L 
   ; Compare user_input[i] with 'L'
   0x08049a2c <+59>:  cmp    DWORD PTR [ebp-0x14],0x4c
   ; jump to SECTION L if user_input[i] == 'L'
   0x08049a30 <+63>:  je     0x8049a40 <blue+79>
   ; 0x52 = ascii R (right)
   ; Compare user_input[i] with 'R'
   0x08049a32 <+65>:  cmp    DWORD PTR [ebp-0x14],0x52
   ; jump to SECTION R if user_input[i] == 'R'
   0x08049a36 <+69>:  je     0x8049a4a <blue+89>
   ; 0xa = ascii newline
   ; Compare user_input[i] with '\n'
   0x08049a38 <+71>:  cmp    DWORD PTR [ebp-0x14],0xa
   ; jump to SECTION \n if user_input[i] == '\n'
   0x08049a3c <+75>:  je     0x8049a55 <blue+100>
   ; if none matched jump to SECTION NONE
   0x08049a3e <+77>:  jmp    0x8049a5e <blue+109>
   
;SECTION L -> GO HERE IF user_input[i] == 'L'
   ;
   ; [ebp-0x4] was holding the graph variable address 0x804c160
   ; eax := 0x804c160
   0x08049a40 <+79>:  mov    eax,DWORD PTR [ebp-0x4]
   ; eax := the value at [0x804c160] => 0x0804c19c
   0x08049a43 <+82>:  mov    eax,DWORD PTR [eax]
   ; [ebp-0x4] now holds the NEW (next) address 0x0804c19c
   0x08049a45 <+84>:  mov    DWORD PTR [ebp-0x4],eax
   ; jump to section CONT
   0x08049a48 <+87>:  jmp    0x8049a71 <blue+128>

;SECTION R -> GO HERE IF user_input[i] == 'R'
   ;
   ; [ebp-0x4] holds an address belonging to the graph variable
   ; eax := [ebp-0x4]
   0x08049a4a <+89>:  mov    eax,DWORD PTR [ebp-0x4]
   ; eax := value at [eax+0x8]
   ; based on my findings of graph variable this should
   ; also be a valid address (because has an offset of 8)
   0x08049a4d <+92>:  mov    eax,DWORD PTR [eax+0x8]
   ; [ebp-0x4] now holds NEW address but one found at an offset -0x8
   0x08049a50 <+95>:  mov    DWORD PTR [ebp-0x4],eax
   ; jump to section CONT
   0x08049a53 <+98>:  jmp    0x8049a71 <blue+128>

;SECTION \n -> GO HERE IF user_input[i] == '\n'
   ; flag gets set to 1
   ; flag := 1
   0x08049a55 <+100>: mov    DWORD PTR [ebp-0x10],0x1
   ; jump to section CONT
   0x08049a5c <+107>: jmp    0x8049a71 <blue+128>

;SECTION NONE
   ; flag is set to 1
   ; flag := 1
   0x08049a5e <+109>: mov    DWORD PTR [ebp-0x10],0x1
   0x08049a65 <+116>: mov    DWORD PTR [esp],0x804a3bb
   ; puts('boom')
   0x08049a6c <+123>: call   0x80487b4 <puts@plt>

;SECTION CONT1 -> GO HERE AFTER 'L', 'R', '\n' SECTIONS
   ; Compare flag with 0
   0x08049a71 <+128>: cmp    DWORD PTR [ebp-0x10],0x0
   ; jump to section CONT2 if flag != 0
   0x08049a75 <+132>: jne    0x8049a8a <blue+153>
   ; eax := [ebp-0x4] that holds the NEW address from the graph variable
   0x08049a77 <+134>: mov    eax,DWORD PTR [ebp-0x4]
   ; based on what I found on about the graph variable
   ; at offset 0x4 there is some value that is not a  valid
   ; address
   ;eax := [eax+0x4]  -> eax contains the value at an offset 0x4 from
   ; the SECOND address (i'll call it var2)
   0x08049a7a <+137>: mov    eax,DWORD PTR [eax+0x4]
   ; [ebp-0x8] was var1 which contained the value at offset of -0x4 to
   ; the FIRST address (the one we started with) of the graph variable
   ;
   ; eax now also contains some value (var2) with an offset of -0x4 but from the
   ; SECOND address
   ;
   ; var1 = var1 XOR var2 
   0x08049a7d <+140>: xor    DWORD PTR [ebp-0x8],eax
   ; i++
   0x08049a80 <+143>: add    DWORD PTR [ebp-0xc],0x1
   ; Compare i with 14
   0x08049a84 <+147>: cmp    DWORD PTR [ebp-0xc],0xe
   ; jump if i <= 14
   ; our input should be no more than 14 characters
   0x08049a88 <+151>: jle    0x8049a15 <blue+36>
   
;SECTION CONT2 -> GO HERE IF flag != 0
   ; this is the end of the function so I'm pretty sure the flag
   ; tells if we reached the end of our input (reached newline) or 
   ; that we typed an invalid character
   0x08049a8a <+153>: mov    DWORD PTR [esp],0x804a3c0
   0x08049a91 <+160>: call   0x8048744 <printf@plt>
   0x08049a96 <+165>: mov    eax,ds:0x804c240
   0x08049a9b <+170>: mov    DWORD PTR [esp],eax
   0x08049a9e <+173>: call   0x8048734 <fflush@plt>
   0x08049aa3 <+178>: mov    DWORD PTR [esp],0x1
   0x08049aaa <+185>: call   0x80487a4 <sleep@plt>
   0x08049aaf <+190>: mov    DWORD PTR [esp],0x804a3eb
   0x08049ab6 <+197>: call   0x80487b4 <puts@plt>
   0x08049abb <+202>: mov    DWORD PTR [esp],0x7a120
   0x08049ac2 <+209>: call   0x8048724 <usleep@plt>
   0x08049ac7 <+214>: mov    eax,ds:0x804a384
   ; Compare var1 with the value at address ds:0x804a384
   0x08049acc <+219>: cmp    DWORD PTR [ebp-0x8],eax
   0x08049acf <+222>: jne    0x8049aec <blue+251>
   0x08049ad1 <+224>: mov    DWORD PTR [esp],0x804a3fc
   0x08049ad8 <+231>: call   0x80487b4 <puts@plt>
   0x08049add <+236>: mov    eax,ds:0x804c140
   0x08049ae2 <+241>: sub    eax,0x1
   0x08049ae5 <+244>: mov    ds:0x804c140,eax
   0x08049aea <+249>: jmp    0x8049af9 <blue+264>
   0x08049aec <+251>: mov    eax,ds:0x804c140
   0x08049af1 <+256>: add    eax,0x1
   0x08049af4 <+259>: mov    ds:0x804c140,eax
   0x08049af9 <+264>: leave  
   0x08049afa <+265>: ret    
```

Well, it's a mess looking at this disassembly, and my comments are for sure confusing, so I'll show some screenshots from the IDA graph view.  But first, lets summarize:
- The only valid input characters are 'L', 'R' and '\n'
- Input should be no more thatn 14 characters long
- Also now I'm sure that our graph variable is kind of a linked list with structures of the form:

```c
struct graph{    // example address 0x804c160
	int next_1;  // 0x804c160 + 0x0 -> 0x0804c19c
	int value;   // 0x804c160 + 0x4 -> 0x47bbfa96
	int next_2;  // 0x804c160 + 0x8 -> 0x0804c178
}
```
And the connected elements are forming a.... graph. And at each node you could go 'L'eft and 'R'ight on the graph. 

- At the end our var1 is compared to a value at address 0x804a384 which is equal to:

```
pwndbg> x/wx 0x804a384
0x804a384 <solution>:	0x40475194
```
That means after all iterations var1 should be equal to 0x40475194. 

So we enter a path in the form 'LLRRLRLRLLR' and the values of each node with pass through and the expected result shuld be 0x40475194.

And below are screenshots from the IDA graph view (if it's hard to see open them in a new tab):

![bomb_blue_1](/images/basic_reverse_engineering/bomb_blue_1.png)

![bomb_blue_2](/images/basic_reverse_engineering/bomb_blue_2.png)

![bomb_blue_3](/images/basic_reverse_engineering/bomb_blue_3.png)

![bomb_blue_4](/images/basic_reverse_engineering/bomb_blue_4.png)

I found all nodes and their values manually, and wrote the following python script that bruteforces the solution by trying all possible paths.

```python
#!/usr/bin/env python3

class graph:
  def __init__(self, value):
    self.value = value
    self.left = None
    self.right = None

c160 = graph(0x47bbfa96)
c19c = graph(0x0c4079ef)
c1cc = graph(0x4b846cb6)
c1f0 = graph(0x16848c16)
c184 = graph(0x634284d3)


c1c0 = graph(0x237a3a88)
c1e4 = graph(0x3a4ad3ff)


c1a8 = graph(0x425ebd95)
c178 = graph(0x23daf3f1)
c1d8 = graph(0x1fba9a98)
c214 = graph(0x770ea82a)


c1fc = graph(0x499ee4ce)
c190 = graph(0x344c4eb1)

c1b4 = graph(0x07ace749)


c160.right = c178
c19c.right = c214
c1cc.right = c184
c1f0.right = c178
c184.right = c1c0
c1c0.right = c184
c1e4.right = c1c0
c1a8.right = c184
c178.right = c1a8
c1d8.right = c1c0
c214.right = c1fc
c1fc.right = c1b4
c190.right = c1fc
c1b4.right = c1a8


c160.left = c19c
c19c.left = c1cc
c1cc.left = c1f0
c1f0.left = c184
c184.left = c19c

c1c0.left = c1e4
c1e4.left = c19c

c1a8.left = c178
c178.left = c1d8
c1d8.left = c214
c214.left = c1cc

c1fc.left = c190
c190.left = c1f0

c1b4.left = c1cc

solution = 0x40475194

def find_key(directions):
  for i,d in enumerate(directions):
    if i == 0:
      k = c160
      xored = k.value
    if d == 'L':
      k = k.left
      v = k.value
      xored = xored ^ v
    if d == 'R':
      k = k.right
      v = k.value
      xored = xored ^ v

  if xored == solution:
    print("Sucess! Found Key!")
    print("Key: %s" % (directions))
    input()

for pos in range(2,15):
  print("Positions: %d" % (pos))
  print("Combinations to try: %d" % (2**pos))
  for i in range(2**pos): 
    # format binary with fixed length of 'pos' positions
    format_string = '{0:0'+str(pos)+'b}'
    binary = format_string.format(i)
    combination = binary.replace('0','L').replace('1','R')
    find_key(combination)
  print("==========================")
```

```
$ ./blue.py 
Positions: 2
Combinations to try: 4
==========================
Positions: 3
Combinations to try: 8
==========================
Positions: 4
Combinations to try: 16
Sucess! Found Key!
Key: LLRR
```

![bomb_blue_5](/images/basic_reverse_engineering/bomb_blue_5.png)

## Red

When you run the RED option three hexadecimal numbers are generated:

![bomb_red_1](/images/basic_reverse_engineering/bomb_red_1.png)

This time the preflight function is important.

```nasm
pwndbg> disass red_preflight 
Dump of assembler code for function red_preflight:
   0x080497a4 <+0>: push   ebp
   0x080497a5 <+1>: mov    ebp,esp
   0x080497a7 <+3>: sub    esp,0x28
   0x080497aa <+6>: call   0x80487c4 <rand@plt>
   0x080497af <+11>:  and    eax,0x7fffffff
   ; 0x804c264 points to variable I'll call rnd1
   ; rnd1 := random && 0x7fffffff
   0x080497b4 <+16>:  mov    ds:0x804c264,eax
   0x080497b9 <+21>:  call   0x80487c4 <rand@plt>
   ; 0x804c268 is rnd2 := random
   0x080497be <+26>:  mov    ds:0x804c268,eax
   0x080497c3 <+31>:  call   0x80487c4 <rand@plt>
   ; 0x804c26c is rnd3 := random
   ; Thes three random numbers are consecutive and
   ; can be referenced as an array rnd[i] with first element rnd1
   0x080497c8 <+36>:  mov    ds:0x804c26c,eax
   ; [ebp-0x4] is an interatior
   ; At address 0x080497fc it is incremented and
   ; after that a compare and a jump
   ; i := 0
   0x080497cd <+41>:  mov    DWORD PTR [ebp-0x4],0x0
   0x080497d4 <+48>:  jmp    0x8049800 <red_preflight+92>
   0x080497d6 <+50>:  mov    eax,DWORD PTR [ebp-0x4]
   ; iterate through rnd[i]
   ; eax := i*4 + &rnd1 equivalent to rnd[i]
   0x080497d9 <+53>:  mov    eax,DWORD PTR [eax*4+0x804c264]
   0x080497e0 <+60>:  mov    DWORD PTR [esp+0x4],eax
   ; printf('CLOCK SYNC: rnd[i]')
   0x080497e4 <+64>:  mov    DWORD PTR [esp],0x804a234
   0x080497eb <+71>:  call   0x8048744 <printf@plt>
   0x080497f0 <+76>:  mov    DWORD PTR [esp],0x7a120
   0x080497f7 <+83>:  call   0x8048724 <usleep@plt>
   ; i++
   0x080497fc <+88>:  add    DWORD PTR [ebp-0x4],0x1
   ; compare i with 0x2
   0x08049800 <+92>:  cmp    DWORD PTR [ebp-0x4],0x2
   ; loop if i <= 0x2 (loop through the random numbers)
   0x08049804 <+96>:  jle    0x80497d6 <red_preflight+50>
   0x08049806 <+98>:  mov    DWORD PTR [esp],0x804a25c
   0x0804980d <+105>: call   0x8048744 <printf@plt>
   0x08049812 <+110>: mov    eax,ds:0x804c220
   0x08049817 <+115>: mov    DWORD PTR [esp+0x8],eax
   0x0804981b <+119>: mov    DWORD PTR [esp+0x4],0x15
   ; 0x804c24c = user_input
   0x08049823 <+127>: mov    DWORD PTR [esp],0x804c24c
   0x0804982a <+134>: call   0x8048704 <fgets@plt>
   0x0804982f <+139>: leave  
   0x08049830 <+140>: ret    
End of assembler dump.

pwndbg> disass red
Dump of assembler code for function red:
   0x08049831 <+0>: push   ebp
   0x08049832 <+1>: mov    ebp,esp
   0x08049834 <+3>: sub    esp,0x18
   0x08049837 <+6>: call   0x80497a4 <red_preflight>
   ; [ebp-0x4] := 0x804a29c 
   ; where 0x804a29c points to an array with alphanumeric characters
   ; [ebp-0x4] is characters := "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
   0x0804983c <+11>:  mov    DWORD PTR [ebp-0x4],0x804a29c
   ; [ebp-0x8] is an iterator i := 0 to 18
   0x08049843 <+18>:  mov    DWORD PTR [ebp-0x8],0x0
   0x0804984a <+25>:  jmp    0x80498ba <red+137>
   0x0804984c <+27>:  mov    eax,DWORD PTR [ebp-0x8]
   ; 0x804c24c points to the user_input
   ; edx := user_input[i]
   0x0804984f <+30>:  movzx  edx,BYTE PTR [eax+0x804c24c]
   0x08049856 <+37>:  mov    eax,ds:0x804c26c
   ; eax = rnd3 && 0x1f
   0x0804985b <+42>:  and    eax,0x1f
   ; eax := &characters[eax]
   0x0804985e <+45>:  add    eax,DWORD PTR [ebp-0x4]
   ; eax := characters[eax]
   0x08049861 <+48>:  movzx  eax,BYTE PTR [eax]
   0x08049864 <+51>:  cmp    dl,al
   ; jump if user_input[i] == characters[rnd3 && 0x1f]
   0x08049866 <+53>:  je     0x8049877 <red+70>
   0x08049868 <+55>:  mov    eax,ds:0x804c128
   0x0804986d <+60>:  add    eax,0x1
   0x08049870 <+63>:  mov    ds:0x804c128,eax
   ; if user_input[i] != characters -> exit
   0x08049875 <+68>:  jmp    0x80498ca <red+153>
   0x08049877 <+70>:  mov    eax,ds:0x804c26c
   0x0804987c <+75>:  mov    edx,eax
   ; edx := rnd3 >> 0x5
   0x0804987e <+77>:  shr    edx,0x5
   0x08049881 <+80>:  mov    eax,ds:0x804c268
   ; eax := rnd2 << 0x1b
   0x08049886 <+85>:  shl    eax,0x1b
   ; eax := (rnd2 << 0x1b) || (rnd3 >> 0x5)
   0x08049889 <+88>:  or     eax,edx
   ; rnd3 := (rnd2 << 0x1b) || (rnd3 >> 0x5)
   0x0804988b <+90>:  mov    ds:0x804c26c,eax
   0x08049890 <+95>:  mov    eax,ds:0x804c268
   0x08049895 <+100>: mov    edx,eax
   ; edx := rnd2 >> 0x5
   0x08049897 <+102>: shr    edx,0x5
   0x0804989a <+105>: mov    eax,ds:0x804c264
   ; eax := rnd1 << 0x1b
   0x0804989f <+110>: shl    eax,0x1b
   0x080498a2 <+113>: or     eax,edx
   ; rdn2 = (rnd1 << 0x1b) || (rnd2 >> 0x5)
   0x080498a4 <+115>: mov    ds:0x804c268,eax
   0x080498a9 <+120>: mov    eax,ds:0x804c264
   0x080498ae <+125>: shr    eax,0x5
   ; rnd1 := rnd1 >> 0x5
   0x080498b1 <+128>: mov    ds:0x804c264,eax
   ; i++
   0x080498b6 <+133>: add    DWORD PTR [ebp-0x8],0x1
   0x080498ba <+137>: cmp    DWORD PTR [ebp-0x8],0x12
   ; jump if i<= 18
   0x080498be <+141>: jle    0x804984c <red+27>
   0x080498c0 <+143>: mov    DWORD PTR ds:0x804c128,0x0
   0x080498ca <+153>: leave  
   0x080498cb <+154>: ret    
End of assembler dump.
```

And the IDA graph view:

preflight:
![bomb_red_2](/images/basic_reverse_engineering/bomb_red_2.png)

red:
![bomb_red_3](/images/basic_reverse_engineering/bomb_red_3.png)

It's obvious what it does. 
- It generates 3 random numbers
- Based on those random numbers it calculates what input characters to expect

It's trivial to do it in a python script:

```python
#!/usr/bin/env python3

characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
length = 18

rnd1 = int(input("RND1: "), 16) 
rnd2 = int(input("RND2: "), 16) 
rnd3 = int(input("RND3: "), 16) 

key = []
for i in range(length + 1):
  key.append( characters[rnd3 & 0x1f] )
  rnd3 = (rnd2 << 0x1b) | (rnd3 >> 0x5)
  rnd2 = (rnd1 << 0x1b) | (rnd2 >> 0x5)
  rnd1 = rnd1 >> 0x5

print('Key: %s' % (''.join(key)))
```

Run the script and copy the random numbers that the executable generated.

```
$ ./red.py 
RND1: 6B8B4567
RND2: 327B23C6
RND3: 643C9869
Key: KDG3DU32D38EVVXJM64
```

Test the key:

![bomb_red_4](/images/basic_reverse_engineering/bomb_red_4.png)

That's it for now. Part 0x02 will be a write up for the cmubomb executable.
