---
layout: post
date:   2017-06-22 15:12:01 -0600
categories: writeups
description: "Crackme challenges writeup from the Modern Binary Exploitation course."
title:  "Basic Reverse Engineering (writeup) - Part 0x00"
author: "Iliya Dafchev"
---

# Introduction
[I moved this article to my new blog. Click here to read it there.](https://idafchev.github.io/blog/basic_reverse_engineering_part_1/)  

I've started a course on [Modern Binary Exploitation](http://security.cs.rpi.edu/courses/binexp-spring2015/) and throughout this course there are challenges and labs with which to practice exploitation techniques. It starts with an introduction to reverse engineering and I've decided to write about how I solved the challenges and take notes of the things I learned.

This post will focus on the crackme challenges from the "Tools and Basic Reverse Engineering" class.

### If you plan to take the course I highly encourage you not to read any further and try to solve the challenges yourself. You'll learn much more that way.

Now lets start reversing!

## crackme0x00a

The focus of crackme0x00a and crackme0x00b is on strings and checking the strings for interesting information is one of the first things you'll have to do when analysing a binary.

Use *strings*{: style="color: LightGreen"} with the *-a*{: style="color: LightGreen"} switch to search all seactions of the binary.

```
$ strings -a crackme0x00a
...............
 output omitted
...............

Enter password: 
Congrats!
Wrong!
;*2$"
g00dJ0B!
GCC: (Ubuntu/Linaro 4.6.1-9ubuntu3) 4.6.1

...............
 output omitted
...............

$ ./crackme0x00a
Enter password: g00dJ0B!
Congrats!
```

## crackme0x00b

Don't forget to search for strings in different encodings. Use the *-e*{: style="color: LightGreen"} switch to specify the encoding.  
*strings -e l*{: style="color: LightGreen"} searches for 16bit little endian encoding  
*strings -e b*{: style="color: LightGreen"} searches for 16bit big endian encoding  
*strings -e L*{: style="color: LightGreen"} searches for 32bit little endian encoding  
*strings -e B*{: style="color: LightGreen"} searches for 32bit big endian encoding  

```
$ strings -a -e L crackme0x00b
w0wgreat

$ ./crackme0x00b 
Enter password: w0wgreat
Congrats!
```

## crackme0x01

That's the first binary where we'll have to dig into the assembly. These crackme challenges are quite easy and for solving them I only used *objdump*{: style="color: LightGreen"} and occasionally *gdb (pwndbg)*{: style="color: LightGreen"}.

I've omitted the unnecessary output of objdump and shown only the relevant sections. Also I use the option *--no-show-raw-insn*{: style="color: LightGreen"} which removes the opcodes from the objdump output.

```
$ objdump -d --no-show-raw-insn -M intel crackme0x01
```

```nasm
080483e4 <main>:
 80483e4: push   ebp
 80483e5: mov    ebp,esp
 80483e7: sub    esp,0x18
 80483ea: and    esp,0xfffffff0
 80483ed: mov    eax,0x0
 80483f2: add    eax,0xf
 80483f5: add    eax,0xf
 80483f8: shr    eax,0x4
 80483fb: shl    eax,0x4
 80483fe: sub    esp,eax
 8048400: mov    DWORD PTR [esp],0x8048528
 8048407: call   804831c <printf@plt>
 804840c: mov    DWORD PTR [esp],0x8048541
 8048413: call   804831c <printf@plt>
 ; eax := address of [ebp-0x4] (local uninitialized variable)
 8048418: lea    eax,[ebp-0x4]
 ; the variable is saved on the stack at [esp+0x4]
 804841b: mov    DWORD PTR [esp+0x4],eax
 ; save 0x804854c on the stack at [esp]
 ; I used gdb to find that 0x804854c
 ; is the address of the string '%d'
 804841f: mov    DWORD PTR [esp],0x804854c
 ; call scanf("%d", [esp+0x4])
 ; [esp+0x4] = &[ebp-0x4]
 ; It's obvious that [ebp-0x4] is the variable
 ; where our input is saved so I'll call it 'input'
 8048426: call   804830c <scanf@plt>
 ; check if input == 0x149a
 ; and that's out password :)
 804842b: cmp    DWORD PTR [ebp-0x4],0x149a
 8048432: je     8048442 <main+0x5e>
 8048434: mov    DWORD PTR [esp],0x804854f
 804843b: call   804831c <printf@plt>
 8048440: jmp    804844e <main+0x6a>
 8048442: mov    DWORD PTR [esp],0x8048562
 8048449: call   804831c <printf@plt>
 804844e: mov    eax,0x0
 8048453: leave  
 8048454: ret    
```

The function arguments usually are *push*{: style="color: LightGreen"}ed on the stack right before the function call. An alternative way without pushing is to save(write) the arguments at the top of the stack. Also it's important to know that arguments are pushed in reversed order. So for the function *example*{: style="color: LightGreen"}(*arg1*{: style="color: LightSalmon"}, *arg2*{: style="color: LightSalmon"}, *arg3*{: style="color: LightSalmon"}, *arg4*{: style="color: LightSalmon"}) the argument *arg4*{: style="color: LightSalmon"} will be pushed first, then *arg3*{: style="color: LightSalmon"}, *arg2*{: style="color: LightSalmon"} and at last *arg1*{: style="color: LightSalmon"}. So by watching what gets pushed on the stack prior to calling a function we can find its arguments and deduce the purpose of the variables.

Right before the *scanf*{: style="color: LightGreen"} call the address *0x804854c*{: style="color: LightSalmon"} is saved at the top of the stack. So that is the first argument of *scanf*{: style="color: LightGreen"} and that's how I know it must be a string (a format string). And right before *0x804854c*{: style="color: LightSalmon"} the address of our local variable is saved on the stack. That means that's the second argument of *scanf*{: style="color: LightGreen"} and is the variable where our input is saved.

I use python to find the decimal representation of 0x149a.

```
$ python -c "print 0x149a"
5274
$ ./crackme0x01
IOLI Crackme Level 0x01
Password: 5274
Password OK :)
```

Aaaand success!

## crackme0x02

A thing to keep in mind is that local variables are referenced by negative offset with respect ot *ebp*{: style="color: LightGreen"} (because the stack grows to lower addresses) like [ebp-0x8], [ebp-0x4], [ebp-0xc] or by a positive offset with respect to *esp*{: style="color: LightGreen"} (because *esp*{: style="color: LightGreen"} points to the top of the stack - lowest current address) like [esp+0x4], [esp+0x8]. Basically *ebp*{: style="color: LightGreen"} with negative offset and *esp* with positive offset points to memory address at the current stack frame.

When there's a reference that uses *ebp*{: style="color: LightGreen"} with a positive offset that means the memory address is at the previous stack frame which means it's referencing an argument passed to the current function.

![stack_vars](/images/basic_reverse_engineering/stack_vars.png)

```
$ objdump -d --no-show-raw-insn -M intel crackme0x02
```

```nasm
080483e4 <main>:
 80483e4: push   ebp
 80483e5: mov    ebp,esp
 80483e7: sub    esp,0x18
 80483ea: and    esp,0xfffffff0
 80483ed: mov    eax,0x0
 80483f2: add    eax,0xf
 80483f5: add    eax,0xf
 80483f8: shr    eax,0x4
 80483fb: shl    eax,0x4
 80483fe: sub    esp,eax
 8048400: mov    DWORD PTR [esp],0x8048548
 8048407: call   804831c <printf@plt>
 804840c: mov    DWORD PTR [esp],0x8048561
 8048413: call   804831c <printf@plt>
 ; [ebp-0x4] is again our 'input' variable
 ; eax := &input
 8048418: lea    eax,[ebp-0x4]
 804841b: mov    DWORD PTR [esp+0x4],eax
 ; 0x804856c points to the string "%d"
 804841f: mov    DWORD PTR [esp],0x804856c
 ; call scanf("%d", &input)
 8048426: call   804830c <scanf@plt>
 ; I'll call [ebp-0x8] var1 := 0x5a
 804842b: mov    DWORD PTR [ebp-0x8],0x5a
 ; and [ebp-0xc] is var2 := 0x1ec
 8048432: mov    DWORD PTR [ebp-0xc],0x1ec
 ; edx := var2
 8048439: mov    edx,DWORD PTR [ebp-0xc]
 ; eax := &var1
 804843c: lea    eax,[ebp-0x8]
 ; equivalent to var1 := var1 + var2
 804843f: add    DWORD PTR [eax],edx
 8048441: mov    eax,DWORD PTR [ebp-0x8]
 ; var1 := var1 * var1
 8048444: imul   eax,DWORD PTR [ebp-0x8]
 ; var2 := var1
 8048448: mov    DWORD PTR [ebp-0xc],eax
 804844b: mov    eax,DWORD PTR [ebp-0x4]
 ; check if input == var2
 ; but now var2 = (0x5a + 0x1ec)^2
 804844e: cmp    eax,DWORD PTR [ebp-0xc]
 8048451: jne    8048461 <main+0x7d>
 8048453: mov    DWORD PTR [esp],0x804856f
 804845a: call   804831c <printf@plt>
 804845f: jmp    804846d <main+0x89>
 8048461: mov    DWORD PTR [esp],0x804857f
 8048468: call   804831c <printf@plt>
 804846d: mov    eax,0x0
 8048472: leave  
 8048473: ret
```

Again it's obvious which is our 'input' variable. The other local variables are also easy to spot because of the negative offset to *ebp*{: style="color: LightGreen"} and the assignment of a constant value.

```
$ python -c "print (0x5a+0x1ec)**2"
338724
$
$ ./crackme0x02
IOLI Crackme Level 0x02
Password: 338724
Password OK :)
```

## crackme0x03

This time we have two more functions - test() and shift(). The main() function is almost the same. This time var2 and our input is passed to the function test() and if our input is correct calls shift(string) which decodes the passed string and prints it. The encoded string that is passed to shift() is just the message that tells if our password was correct or not.

Start reading from the main function.

```
$ objdump -d --no-show-raw-insn -M intel crackme0x03
```
```nasm
08048414 <shift>:
 8048414: push   ebp
 8048415: mov    ebp,esp
 8048417: sub    esp,0x98
 ; [ebp-0x7c] is initialized to 0
 ; look at addresses 8048449 - 804844e 
 ; It's incremented and execution returns to 8048424
 ; It's a loop! So [ebp-0x7c] is our counter i := 0
 804841d: mov    DWORD PTR [ebp-0x7c],0x0
 ; [ebp+0x8] is our arg0 which is an address
 ; You can see below that strlen(arg0) is called
 ; So that address points to a string
 ; 0x80485ec -> string1
 ; 0x80485fe -> string2
 8048424: mov    eax,DWORD PTR [ebp+0x8]
 8048427: mov    DWORD PTR [esp],eax
 804842a: call   8048340 <strlen@plt>
 ; compare i with length of the string
 804842f: cmp    DWORD PTR [ebp-0x7c],eax 
 ; jump if i >= length of the string
 8048432: jae    8048450 <shift+0x3c> 
 ; eax := &var3 (local uninitialized variable)
 8048434: lea    eax,[ebp-0x78]
 8048437: mov    edx,eax
 ; edx := i + &var3 
 ; equivalent to edx := &var3[i]
 ; which means var3 is an array / string
 8048439: add    edx,DWORD PTR [ebp-0x7c] 
 ; eax := i
 804843c: mov    eax,DWORD PTR [ebp-0x7c]
 ; eax := i + arg0 = &arg0[i]
 804843f: add    eax,DWORD PTR [ebp+0x8]
 ; eax := arg0[i]
 8048442: movzx  eax,BYTE PTR [eax]
 ; al := arg0[i] - 0x3
 8048445: sub    al,0x3
 ; var3[i] := al = arg0[i] - 0x3
 ; so this loop iterates through the characters of arg0
 ; subtracts 0x3 from them and saves the result in the 
 ; array var3
 8048447: mov    BYTE PTR [edx],al 
 8048449: lea    eax,[ebp-0x7c]
 ; i++
 804844c: inc    DWORD PTR [eax]
 ; loop
 804844e: jmp    8048424 <shift+0x10>
 ; eax := &var3 (now contains the decoded string)
 8048450: lea    eax,[ebp-0x78] 
 ; eax := i + &var3 = &var3[i] (now the last element)
 8048453: add    eax,DWORD PTR [ebp-0x7c] 
 ; var3[i] = 0x0 -> null terminate the decoded string
 8048456: mov    BYTE PTR [eax],0x0 
 ; eax := &var3
 8048459: lea    eax,[ebp-0x78]
 804845c: mov    DWORD PTR [esp+0x4],eax 
 8048460: mov    DWORD PTR [esp],0x80485e8
 ; call printf(&var3)
 ; prints the decoded string
 ; 'Password OK!!! :)' if input was correct
 8048467: call   8048350 <printf@plt>
 804846c: leave  
 804846d: ret    

0804846e <test>:
 804846e: push   ebp
 804846f: mov    ebp,esp
 8048471: sub    esp,0x8
 ; [ebp+0x8] is arg0 := input
 8048474: mov    eax,DWORD PTR [ebp+0x8]
 ; compare arg1 (var2) and arg0 (input)
 8048477: cmp    eax,DWORD PTR [ebp+0xc]
 804847a: je     804848a <test+0x1c>
 ; if input1 != var2 call shift(0x80485ec)
 804847c: mov    DWORD PTR [esp],0x80485ec 
 8048483: call   8048414 <shift>
 8048488: jmp    8048496 <test+0x28>
 ; if input1 == var2 call shift(0x80485fe)
 804848a: mov    DWORD PTR [esp],0x80485fe
 8048491: call   8048414 <shift>
 8048496: leave  
 8048497: ret    

08048498 <main>:
 8048498: push   ebp
 8048499: mov    ebp,esp
 804849b: sub    esp,0x18
 804849e: and    esp,0xfffffff0
 80484a1: mov    eax,0x0
 80484a6: add    eax,0xf
 80484a9: add    eax,0xf
 80484ac: shr    eax,0x4
 80484af: shl    eax,0x4
 80484b2: sub    esp,eax
 80484b4: mov    DWORD PTR [esp],0x8048610
 80484bb: call   8048350 <printf@plt>
 80484c0: mov    DWORD PTR [esp],0x8048629
 80484c7: call   8048350 <printf@plt>
 ; [ebp-0x4] is again our 'input' variable
 ; eax := &input
 80484cc: lea    eax,[ebp-0x4]
 80484cf: mov    DWORD PTR [esp+0x4],eax
 ; 0x8048634 points to the string "%d"
 80484d3: mov    DWORD PTR [esp],0x8048634
 ; call scanf("%d", &input)
 80484da: call   8048330 <scanf@plt>
 ; I'll call [ebp-0x8] var1 := 0x5a
 80484df: mov    DWORD PTR [ebp-0x8],0x5a
 ; and [ebp-0xc] is var2 := 0x1ec
 80484e6: mov    DWORD PTR [ebp-0xc],0x1ec
 80484ed: mov    edx,DWORD PTR [ebp-0xc] 
 80484f0: lea    eax,[ebp-0x8]
 ; equivalent to var1 := var1 + var2
 80484f3: add    DWORD PTR [eax],edx
 80484f5: mov    eax,DWORD PTR [ebp-0x8]
 ; var1 := var1 * var1
 80484f8: imul   eax,DWORD PTR [ebp-0x8]
 ; var2 := var1
 80484fc: mov    DWORD PTR [ebp-0xc],eax
 80484ff: mov    eax,DWORD PTR [ebp-0xc]
 ; save var2 at [esp+0x4] (arg1)
 8048502: mov    DWORD PTR [esp+0x4],eax 
 8048506: mov    eax,DWORD PTR [ebp-0x4]
 ; save input at [esp] (arg0)
 8048509: mov    DWORD PTR [esp],eax 
 ; call test(input, var2), where var2 = (0x5a + 0x1ec)^2 = 338724
 804850c: call   804846e <test> 
 8048511: mov    eax,0x0
 8048516: leave  
 8048517: ret    
```

```
$ ./crackme0x03
IOLI Crackme Level 0x03
Password: 338724
Password OK!!! :)
```

## crackme0x04

When the offset to a local variable is large (for example [ebp-0x78]) this usually means it's a buffer (or that the function has many local variables). Because x86 architecture is little endian the strings are stored in memory in reverse. That means the starting address of the string is at the lowest memory address of the buffer. 

```
$ objdump -d --no-show-raw-insn -M intel crackme0x04
```

```nasm
08048484 <check>:
 8048484: push   ebp
 8048485: mov    ebp,esp
 8048487: sub    esp,0x28
 ; [ebp-0x8] is var1 := 0
 804848a: mov    DWORD PTR [ebp-0x8],0x0
 ; [ebp-0xc] is set to 0
 ; At addresses 80484f4 - 80484f9 it's incremented
 ; and execution returns to 8048498
 ; Which means [ebp-0xc] is a counter i := 0
 8048491: mov    DWORD PTR [ebp-0xc],0x0
 ; eax := arg0 which is our &input
 8048498: mov    eax,DWORD PTR [ebp+0x8]
 804849b: mov    DWORD PTR [esp],eax
 ; strlen(&input)
 804849e: call   8048384 <strlen@plt> 
 ; compare the inputs length with i
 80484a3: cmp    DWORD PTR [ebp-0xc],eax
 ; jump if i >= inputs length 
 ; We iterate through every character of our input
 80484a6: jae    80484fb <check+0x77>
 ; eax := i
 80484a8: mov    eax,DWORD PTR [ebp-0xc]
 ; eax := i + &input
 ; equivalent to eax := &input[i]
 80484ab: add    eax,DWORD PTR [ebp+0x8]
 ; eax := input[i]
 80484ae: movzx  eax,BYTE PTR [eax]
 ; [ebp-0xd] is a local variable var2
 ; var2 := al = input[i]
 80484b1: mov    BYTE PTR [ebp-0xd],al
 ; eax := &var3 (uninitialized vaariable)
 80484b4: lea    eax,[ebp-0x4]
 ; save  &var3 at [esp+0x8]
 80484b7: mov    DWORD PTR [esp+0x8],eax
 ; save address 0x8048638 at [esp+0x4]
 ; determined with gdb that it points to the string "%d"
 80484bb: mov    DWORD PTR [esp+0x4],0x8048638 
 80484c3: lea    eax,[ebp-0xd]
 ; save &var2 (&input[i]) at [esp]
 80484c6: mov    DWORD PTR [esp],eax
 ; call sscanf(&input[i], "%d", &var3)
 ; parse the current character of input as integer
 ; and save it in var3
 80484c9: call   80483a4 <sscanf@plt> 
 ; edx := var3
 80484ce: mov    edx,DWORD PTR [ebp-0x4]
 ; eax := &var1 
 80484d1: lea    eax,[ebp-0x8]
 ; var1 := var1 + var3
 ; equivalent to 
 ; var1 := var1 + int( input[i] )
 80484d4: add    DWORD PTR [eax],edx
 ; compare var1 with 0xf (decimal 15)
 80484d6: cmp    DWORD PTR [ebp-0x8],0xf
 ; jump if var1 != 15
 ; So the sum of the integer values of all input characters must be equal
 ; to decimal 15
 80484da: jne    80484f4 <check+0x70> 
 80484dc: mov    DWORD PTR [esp],0x804863b
 80484e3: call   8048394 <printf@plt>
 80484e8: mov    DWORD PTR [esp],0x0
 80484ef: call   80483b4 <exit@plt>
 80484f4: lea    eax,[ebp-0xc]
 ; i++
 80484f7: inc    DWORD PTR [eax]
 ; loop
 80484f9: jmp    8048498 <check+0x14>
 80484fb: mov    DWORD PTR [esp],0x8048649
 8048502: call   8048394 <printf@plt>
 8048507: leave  
 8048508: ret    

08048509 <main>:
 8048509: push   ebp
 804850a: mov    ebp,esp
 804850c: sub    esp,0x88
 8048512: and    esp,0xfffffff0
 8048515: mov    eax,0x0
 804851a: add    eax,0xf
 804851d: add    eax,0xf
 8048520: shr    eax,0x4
 8048523: shl    eax,0x4
 8048526: sub    esp,eax
 8048528: mov    DWORD PTR [esp],0x804865e
 804852f: call   8048394 <printf@plt>
 8048534: mov    DWORD PTR [esp],0x8048677
 804853b: call   8048394 <printf@plt>
 ; [ebp-0x78] holds our 'input' which is probably a buffer
 8048540: lea    eax,[ebp-0x78]
 8048543: mov    DWORD PTR [esp+0x4],eax
 ; 0x8048682 points to the format string
 ; I used gdb to determine that the string is "%s"
 ; which confirms that our input is a string and will
 ; be stored in a buffer
 8048547: mov    DWORD PTR [esp],0x8048682
 ; scanf("%s", &input)
 804854e: call   8048374 <scanf@plt>
 8048553: lea    eax,[ebp-0x78]
 8048556: mov    DWORD PTR [esp],eax
 ; call check(&input)
 8048559: call   8048484 <check> 
 804855e: mov    eax,0x0
 8048563: leave  
 8048564: ret    

```

```
$ gdb

pwndbg> file crackme0x04
Reading symbols from crackme0x04...(no debugging symbols found)...done.

pwndbg> x/s 0x8048638
0x8048638:  "%d"

```

```
$ ./crackme0x04
IOLI Crackme Level 0x04
Password: 555
Password OK!

$ ./crackme0x04
IOLI Crackme Level 0x04
Password: 5511111
Password OK!
```

## crackme0x05

Basically the same as crackme0x04 but this time the sum of the individual digits must be decimal 16 and a bonus condition (checked by parell() function) that the whole input number must be even.

```
$ objdump -d --no-show-raw-insn -M intel crackme0x05
```

```nasm
08048484 <parell>:
 8048484: push   ebp
 8048485: mov    ebp,esp
 8048487: sub    esp,0x18
 ; [ebp-0x4] is var4 (local uninitialized variable)
 ; eax := &var4 
 804848a: lea    eax,[ebp-0x4]
 ; save &var4 at [esp+0x8]
 804848d: mov    DWORD PTR [esp+0x8],eax
 ; save address 0x8048668 at [esp+0x4]
 ; 0x8048668 points to format string "%d"
 8048491: mov    DWORD PTR [esp+0x4],0x8048668
 8048499: mov    eax,DWORD PTR [ebp+0x8] 
 ; save &input at [esp]
 804849c: mov    DWORD PTR [esp],eax
 ; call sscanf(&input, "%d", &var4)
 804849f: call   80483a4 <sscanf@plt> 
 ; eax := var4
 ; equivalent to eax := int( input )
 80484a4: mov    eax,DWORD PTR [ebp-0x4]
 ; eax := var4 && 0x1
 ; eax := input && 0x1
 80484a7: and    eax,0x1 
 ; test eax, eax does a bitwise AND
 ; and sets ZF if the result is 0 (possible only when eax = 0)
 80484aa: test   eax,eax 
 ; jump if eax != 0
 ; To go to 'Password OK' eax ( the result of input && 0x1 ) must be equal to 0
 ; This is possible only if input is an even number
 80484ac: jne    80484c6 <parell+0x42>
 80484ae: mov    DWORD PTR [esp],0x804866b
 ; prints 'Password OK'
 80484b5: call   8048394 <printf@plt>
 80484ba: mov    DWORD PTR [esp],0x0
 80484c1: call   80483b4 <exit@plt>
 80484c6: leave  
 80484c7: ret    

080484c8 <check>:
 80484c8: push   ebp
 80484c9: mov    ebp,esp
 80484cb: sub    esp,0x28
 ; [ebp-0x8] is var1 := 0
 80484ce: mov    DWORD PTR [ebp-0x8],0x0
 ; [ebp-0xc] is set to 0
 ; At addresses 804852b - 8048530 it's incremented
 ; and execution returns to 80484dc
 ; Which means [ebp-0xc] is a counter i := 0
 80484d5: mov    DWORD PTR [ebp-0xc],0x0
 ; eax := arg0 which is our &input
 80484dc: mov    eax,DWORD PTR [ebp+0x8]
 80484df: mov    DWORD PTR [esp],eax
 ; strlen(&input)
 80484e2: call   8048384 <strlen@plt>
 ; compare the inputs length with i
 80484e7: cmp    DWORD PTR [ebp-0xc],eax 
 ; jump if i >= inputs length 
 ; We iterate through every character of our input
 80484ea: jae    8048532 <check+0x6a>
 ; eax := i
 80484ec: mov    eax,DWORD PTR [ebp-0xc] 
 ; eax := i + &input
 ; equivalent to eax := &input[i]
 80484ef: add    eax,DWORD PTR [ebp+0x8]
 ; eax := input[i]
 80484f2: movzx  eax,BYTE PTR [eax]
 ; [ebp-0xd] is a local variable var2
 ; var2 := al = input[i]
 80484f5: mov    BYTE PTR [ebp-0xd],al
 ; eax := &var3 (uninitialized vaariable)
 80484f8: lea    eax,[ebp-0x4]
 ; save  &var3 at [esp+0x8]
 80484fb: mov    DWORD PTR [esp+0x8],eax
 ; save address 0x8048668 at [esp+0x4]
 ; determined with gdb that it points to the string "%d"
 80484ff: mov    DWORD PTR [esp+0x4],0x8048668
 8048507: lea    eax,[ebp-0xd]
 ; save &var2 (&input[i]) at [esp]
 804850a: mov    DWORD PTR [esp],eax
 ; call sscanf(&input[i], "%d", &var3)
 ; parse the current character of input as integer
 ; and save it in var3
 804850d: call   80483a4 <sscanf@plt>
 ; edx := var3
 8048512: mov    edx,DWORD PTR [ebp-0x4]
 ; eax := &var1
 8048515: lea    eax,[ebp-0x8]
 ; var1 := var1 + var3
 ; equivalent to 
 ; var1 := var1 + int( input[i] )
 8048518: add    DWORD PTR [eax],edx
 ; compare var1 with 0x10 (decimal 16)
 804851a: cmp    DWORD PTR [ebp-0x8],0x10
 ; jump if var1 != 16
 ; So the sum of the integer values of all input characters must be equal
 ; to decimal 16
 804851e: jne    804852b <check+0x63>
 8048520: mov    eax,DWORD PTR [ebp+0x8]
 ; save &input at [esp]
 8048523: mov    DWORD PTR [esp],eax
 ; call parell(&input)
 8048526: call   8048484 <parell>
 804852b: lea    eax,[ebp-0xc]
 ; i++
 804852e: inc    DWORD PTR [eax]
 ; loop
 8048530: jmp    80484dc <check+0x14>
 8048532: mov    DWORD PTR [esp],0x8048679
 8048539: call   8048394 <printf@plt>
 804853e: leave  
 804853f: ret    

08048540 <main>:
 8048540: push   ebp
 8048541: mov    ebp,esp
 8048543: sub    esp,0x88
 8048549: and    esp,0xfffffff0
 804854c: mov    eax,0x0
 8048551: add    eax,0xf
 8048554: add    eax,0xf
 8048557: shr    eax,0x4
 804855a: shl    eax,0x4
 804855d: sub    esp,eax
 804855f: mov    DWORD PTR [esp],0x804868e
 8048566: call   8048394 <printf@plt>
 804856b: mov    DWORD PTR [esp],0x80486a7
 8048572: call   8048394 <printf@plt>
 ; [ebp-0x78] is our input
 8048577: lea    eax,[ebp-0x78]
 804857a: mov    DWORD PTR [esp+0x4],eax
 ; 0x80486b2 points to the format string "%s"
 804857e: mov    DWORD PTR [esp],0x80486b2
 ; scanf("%s", &input)
 8048585: call   8048374 <scanf@plt>
 804858a: lea    eax,[ebp-0x78]
 804858d: mov    DWORD PTR [esp],eax 
 ; check(&input)
 8048590: call   80484c8 <check>
 8048595: mov    eax,0x0
 804859a: leave  
 804859b: ret    

```

```
$ gdb

pwndbg> file crackme0x05
Reading symbols from crackme0x05...(no debugging symbols found)...done.

pwndbg> x/s 0x8048668
0x8048668:  "%d"
```

```
$ ./crackme0x05
IOLI Crackme Level 0x05
Password: 55222 
Password OK!

$ ./crackme0x05
IOLI Crackme Level 0x05
Password: 25522
Password OK!
```


## crackme0x06

This crackme adds additional condition to the previous one. Now the sum of the input digits must be 16, the input number must be even and an environment variable must exist such that it's name must begin with 'LOL'.

```
$ objdump -d --no-show-raw-insn  -M intel crackme0x06
```

```nasm
080484b4 <dummy>:
 80484b4: push   ebp
 80484b5: mov    ebp,esp
 80484b7: sub    esp,0x18
 ; [ebp-0x4] is set to 0
 ; At addresses 80484e1 - 80484e4 it's incremented
 ; and later execution jumps back to 80484c1
 ; Which means [ebp-0x4] is probably a counter i := 0
 80484ba: mov    DWORD PTR [ebp-0x4],0x0
 80484c1: mov    eax,DWORD PTR [ebp-0x4]
 ; edx := i*4 + 0 
 ; Looks like edx is a counter for iteration through an array
 ; with 4 byte elements
 ; arg1 is such an array. It's elemets are 4 byte addresses
 ; that point to strings (environment variables)
 80484c4: lea    edx,[eax*4+0x0]
 ; eax := arg1
 80484cb: mov    eax,DWORD PTR [ebp+0xc]
 ; compare the value at address &arg1 + edx with 0
 ; equivalent to 
 ; arg1[i] == 0
 ; Which is true when the end of the array is reached
 80484ce: cmp    DWORD PTR [edx+eax*1],0x0
 ; jump if arg1[i] == 0
 ; reached the end of the array on environment variables
 80484d2: je     804850e <dummy+0x5a>
 80484d4: mov    eax,DWORD PTR [ebp-0x4]
 ; ecx := i*4 + 0
 ; It looks like it also is going to be used as iterator
 ; for an array with a 4 byte elements
 80484d7: lea    ecx,[eax*4+0x0]
 ; edx := arg1
 80484de: mov    edx,DWORD PTR [ebp+0xc]
 ; eax := &i
 80484e1: lea    eax,[ebp-0x4]
 ; i++
 80484e4: inc    DWORD PTR [eax]
 ; save 0x3 at [esp+0x8]
 80484e6: mov    DWORD PTR [esp+0x8],0x3
 ; save 0x8048738 at [esp+0x4]
 ; the address points to the string "LOLO"
 80484ee: mov    DWORD PTR [esp+0x4],0x8048738
 80484f6: mov    eax,DWORD PTR [ecx+edx*1]
 ; edx -> arg1
 ; ecx = i*4 but with old value of i
 ; That means save arg1[i-1] at [esp]
 ; which is equivalent to saving the address of the current
 ; environment variable
 80484f9: mov    DWORD PTR [esp],eax
 ; call strncmp(arg1[i-1], "LOLO", 0x3)
 ; compares the first 3 characters of "LOLO" with 
 ; the current env variable arg1[i-1]
 ; Returns 0 if equal
 ; This loop basically searches for env variable
 ; that starts with the string "LOL"
 80484fc: call   80483d8 <strncmp@plt>
 8048501: test   eax,eax
 ; jump if eax != 0 
 ; (jumps when the strings are not equal)
 8048503: jne    80484c1 <dummy+0xd>
 ; [ebp-0x8] is var5
 ; Set var5 := 1 when env variable found
 8048505: mov    DWORD PTR [ebp-0x8],0x1
 804850c: jmp    8048515 <dummy+0x61>
 ; Set var5 := 0  when variable not found
 804850e: mov    DWORD PTR [ebp-0x8],0x0
 ; return var5
 8048515: mov    eax,DWORD PTR [ebp-0x8]
 8048518: leave  
 8048519: ret    

0804851a <parell>:
 804851a: push   ebp
 804851b: mov    ebp,esp
 804851d: sub    esp,0x18
 ; [ebp-0x4] is var4 (local uninitialized variable)
 ; eax := &var4 
 8048520: lea    eax,[ebp-0x4]
 ; save &var4 at [esp+0x8]
 8048523: mov    DWORD PTR [esp+0x8],eax
 ; save address 0x804873d at [esp+0x4]
 ; 0x8048668 points to format string "%d"
 8048527: mov    DWORD PTR [esp+0x4],0x804873d
 804852f: mov    eax,DWORD PTR [ebp+0x8]
 ; save &input at [esp]
 8048532: mov    DWORD PTR [esp],eax
 ; call sscanf(&input, "%d", &var4)
 8048535: call   80483c8 <sscanf@plt>
 ; eax := arg1
 804853a: mov    eax,DWORD PTR [ebp+0xc]
 ; save arg1 at [esp+0x4]
 804853d: mov    DWORD PTR [esp+0x4],eax
 8048541: mov    eax,DWORD PTR [ebp-0x4]
 ; save &var4 at [esp]
 ; var4 is int( input )
 8048544: mov    DWORD PTR [esp],eax
 ; call dummy(var4, arg1)
 8048547: call   80484b4 <dummy>
 804854c: test   eax,eax
 ; jump if eax==0
 ; that is when no env variable "LOL..." is found
 804854e: je     8048586 <parell+0x6c>
 ; [ebp-0x8] is j 
 ; at addresses 804857f - 8048584 it increments
 ; and execution returns to 8048557 
 ; j is probably a counter j := 0
 8048550: mov    DWORD PTR [ebp-0x8],0x0
 8048557: cmp    DWORD PTR [ebp-0x8],0x9
 ; jump if j > 0x9
 804855b: jg     8048586 <parell+0x6c>
 804855d: mov    eax,DWORD PTR [ebp-0x4]
 ; eax := var4 && 0x1
 ; eax := input && 0x1
 8048560: and    eax,0x1
 ; test eax, eax does a bitwise AND
 ; and sets ZF if the result is 0 (possible only when eax = 0)
 8048563: test   eax,eax
 ; jump if eax != 0
 ; To go to 'Password OK' eax ( the result of input && 0x1 ) must be equal to 0
 ; This is possible only if input is an even number
 8048565: jne    804857f <parell+0x65>
 8048567: mov    DWORD PTR [esp],0x8048740
 804856e: call   80483b8 <printf@plt>
 8048573: mov    DWORD PTR [esp],0x0
 804857a: call   80483e8 <exit@plt>
 804857f: lea    eax,[ebp-0x8]
 ; j++
 8048582: inc    DWORD PTR [eax]
 ; loop
 8048584: jmp    8048557 <parell+0x3d>
 8048586: leave  
 8048587: ret    

08048588 <check>:
 8048588: push   ebp
 8048589: mov    ebp,esp
 804858b: sub    esp,0x28
 ; [ebp-0x8] is var1 := 0
 804858e: mov    DWORD PTR [ebp-0x8],0x0
 ; [ebp-0xc] is set to 0
 ; At addresses 80485f2 - 80485f7 it's incremented
 ; and execution returns to 804859c
 ; Which means [ebp-0xc] is a counter i := 0
 8048595: mov    DWORD PTR [ebp-0xc],0x0
 ; eax := arg0 which is our &input
 804859c: mov    eax,DWORD PTR [ebp+0x8]
 804859f: mov    DWORD PTR [esp],eax
 ; strlen(&input)
 80485a2: call   80483a8 <strlen@plt>
 ; compare the inputs length with i
 80485a7: cmp    DWORD PTR [ebp-0xc],eax
 ; jump if i >= inputs length
 ; We iterate through every character of our input
 80485aa: jae    80485f9 <check+0x71>
 ; eax := i
 80485ac: mov    eax,DWORD PTR [ebp-0xc]
 ; eax := i + &input
 ; equivalent to eax := &input[i]
 80485af: add    eax,DWORD PTR [ebp+0x8]
 ; eax := input[i]
 80485b2: movzx  eax,BYTE PTR [eax]
 ; [ebp-0xd] is a local variable var2
 ; var2 := al = input[i]
 80485b5: mov    BYTE PTR [ebp-0xd],al
 ; eax := &var3 (uninitialized vaariable)
 80485b8: lea    eax,[ebp-0x4]
 ; save  &var3 at [esp+0x8]
 80485bb: mov    DWORD PTR [esp+0x8],eax
 ; save address 0x8048668 at [esp+0x4]
 ; determined with gdb that it points to the string "%d"
 80485bf: mov    DWORD PTR [esp+0x4],0x804873d
 80485c7: lea    eax,[ebp-0xd]
 ; save &var2 (&input[i]) at [esp]
 80485ca: mov    DWORD PTR [esp],eax
 ; call sscanf(&input[i], "%d", &var3)
 ; parse the current character of input as integer
 ; and save it in var3
 80485cd: call   80483c8 <sscanf@plt>
 ; edx := var3
 80485d2: mov    edx,DWORD PTR [ebp-0x4]
 ; eax := &var1
 80485d5: lea    eax,[ebp-0x8]
 ; var1 := var1 + var3
 ; equivalent to 
 ; var1 := var1 + int( input[i] )
 80485d8: add    DWORD PTR [eax],edx
 ; compare var1 with 0x10 (decimal 16)
 80485da: cmp    DWORD PTR [ebp-0x8],0x10
 ; jump if var1 != 16
 ; So the sum of the integer values of all input characters must be equal
 ; to decimal 16
 80485de: jne    80485f2 <check+0x6a>
 80485e0: mov    eax,DWORD PTR [ebp+0xc]
 ; save arg1 (array with environment variables) at [esp+0x4]
 80485e3: mov    DWORD PTR [esp+0x4],eax
 80485e7: mov    eax,DWORD PTR [ebp+0x8]
 ; save &input at [esp]
 80485ea: mov    DWORD PTR [esp],eax
 ; call parell(&input, arg1)
 80485ed: call   804851a <parell>
 80485f2: lea    eax,[ebp-0xc]
 ; i++
 80485f5: inc    DWORD PTR [eax]
 ; loop
 80485f7: jmp    804859c <check+0x14>
 80485f9: mov    DWORD PTR [esp],0x804874e
 8048600: call   80483b8 <printf@plt>
 8048605: leave  
 8048606: ret 

08048607 <main>:
 8048607: push   ebp
 8048608: mov    ebp,esp
 804860a: sub    esp,0x88
 8048610: and    esp,0xfffffff0
 8048613: mov    eax,0x0
 8048618: add    eax,0xf
 804861b: add    eax,0xf
 804861e: shr    eax,0x4
 8048621: shl    eax,0x4
 8048624: sub    esp,eax
 8048626: mov    DWORD PTR [esp],0x8048763
 804862d: call   80483b8 <printf@plt>
 8048632: mov    DWORD PTR [esp],0x804877c
 8048639: call   80483b8 <printf@plt>
 ; [ebp-0x78] is our input
 804863e: lea    eax,[ebp-0x78]
 8048641: mov    DWORD PTR [esp+0x4],eax
 ; 0x8048787 points to the format string "%s"
 8048645: mov    DWORD PTR [esp],0x8048787
 ; scanf("%s", &input)
 804864c: call   8048398 <scanf@plt>
 ; [ebp+0x10] = arg1
 ; arg1 is an address that points to the array with
 ; environment variables (checked with gdb)
 8048651: mov    eax,DWORD PTR [ebp+0x10]
 ; save arg1 at [esp+0x4]
 8048654: mov    DWORD PTR [esp+0x4],eax
 8048658: lea    eax,[ebp-0x78]
 ; save &input at [esp]
 804865b: mov    DWORD PTR [esp],eax
 ; call check(&input, arg1)
 804865e: call   8048588 <check>
 8048663: mov    eax,0x0
 8048668: leave  
 8048669: ret     

```

```
$ gdb

pwndbg> file crackme0x06
Reading symbols from crackme0x06...(no debugging symbols found)...done.
pwndbg> br dummy
Breakpoint 1 at 0x80484ba
pwndbg> run
Starting program: /root/Downloads/binary_exp_course/challenges/challenges/crackme0x06 
IOLI Crackme Level 0x06
Password: 55222

Breakpoint 1, 0x080484ba in dummy ()

..............
output omitted
..............

pwndbg> x/s 0x804873d
0x804873d:  "%d"

pwndbg> x/x $ebp + 0xc
0xffffcfe4: 0xffffd16c ; the address of the array (the first element)
pwndbg> x/x 0xffffd16c
0xffffd16c: 0xffffd347 ; the address of first character of the first element in the array
pwndbg> x/s 0xffffd347
0xffffd347: "LS_COLORS=rs=0:"... ; value of the first element in the array
pwndbg>
pwndbg> x/x 0xffffd16c + 0x4  ; next element is after 4 bytes
0xffffd170: 0xffffd903 ; the address of the second element in the array
pwndbg> x/s 0xffffd903
0xffffd903: "XDG_MENU_PREFIX"... ; value of the second element in the array
```

Password is accepted only when environment variable that starts with "LOL" exists.
```
$ ./crackme0x06
IOLI Crackme Level 0x06
Password: 55222
Password Incorrect!
$
$ export LOLO=1
$
$ ./crackme0x06
IOLI Crackme Level 0x06
Password: 55222
Password OK!
```

I'll leave crackme0x07 to crackme0x09. They are almost the same, but stripped.

That's it for part 0x00. Part 0x01 will be about the "bombs" challenges from the "Extended Reverse Engineering" class.
