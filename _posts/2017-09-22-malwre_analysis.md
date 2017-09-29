---
layout: post
date:   2017-09-22 09:12:01 -0600
categories: malware_analysis
description: "I think the title is self-explanatory."
title:  "Analysis of a Trojan downloader"
author: "Iliya Dafchev"
---

# Table of contents

[Triage analysis](#triage_analysis)  
\-\- [Strings](#strings)  
\-\- [Virustotal](#virustotal)  
\-\- [Sandbox](#sandbox)  
\-\- [VM detonation](#vm_detonation)  
[Dynamic analysis (word document)](#dynamic_analysis_doc)  
[Static analysis (shellcode)](#static_analysis_shellcode)  
\-\- [Dump memory (svchost.exe)](#dump_svchost1)  
[Static analysis (svchost.exe)](#static_analysis_svchost)  
\-\- [Dump memory (decrypted svchost.exe)](#dump_svchost2)  
[Static and dynamic analysis (decrypted svchost.exe)](#static_dynamic_analysis_svchost)  
[YARA rule](#yara_rule)  
[Snort rule](#snort_rule)  
[Indicators of Compromise](#ioc)  

This time I wanted to analyse an obfuscated and/or encrypted malware. I chose a [random sample from malwr.com](https://malwr.com/analysis/MzgyYzFkMThiMTM2NDQ3NDk5ZjMwNTQ1YjQ4MDYzODc/) and luckily it was exactly what I was looking for (well, almost...). 

The malware is a MS Word document, which means the attack vector is probably email.

Before I begin, I want to say that if you can't read the text in the screenshots, because it's too small, open them in a new tab.

OK, let's begin.

# <a name="triage_analysis"></a> Triage analysis
## <a name="strings"></a> Strings

The first thing to do when analysing malware is to check the strings. Looking at the screenshots below, you can see strings like "*Public Declare Function*{: style="color: LightSalmon"}...", or "*NtWriteVirtualMemory*{: style="color: LightSalmon"}" which means it probably uses VBA script (as expected), and also makes use of low level native API functions for writing and allocating memory.   

![malware_00](/images/malware_analysis/malware_00.png)
![malware_01](/images/malware_analysis/malware_01.png)

I used [olevba](https://www.decalage.info/python/oletools) to further analyze the document.

```bash
olevba -d 846fe7d28d9134a06a3de32d7a102e481824cca8155549c889fb6809aedcbc2c.doc
```

You can see the results from [olevba](https://www.decalage.info/python/oletools) below. Basically it confirmed the suspicion that the document has VBA macros. On the first screenshot you can see a summary of the analysis.

![malware_02](/images/malware_analysis/malware_02.png)

It also has a large encoded string, which is probably a file or a very long shellcode.  

![malware_03](/images/malware_analysis/malware_03.png)

On these screenshots you can see part of the VBA script, which uses *Document_Open()*{: style="color: LightGreen"} function, to automatically start the script when the document is opened (works only the user enables macros).

![malware_04](/images/malware_analysis/malware_04.png)
![malware_05](/images/malware_analysis/malware_05.png)

## <a name="virustotal"></a> Virustotal

To make the analysis easier and gain some additional information, it's good to check the results from online malware analysis services like [virustotal](https://www.virustotal.com/), [malwr](https://malwr.com/) or [hybrid-analysis](https://www.hybrid-analysis.com/) Many AV solutions classify it as Trojan/Downloader. 

I also took the chance to make a little experiment. First I searched for the malwre by hash. You can compare with the hash from malwr to verify that it's the same sample. The last time it was analysed was 30.08.2017 with 34 detections.

![malware_07a](/images/malware_analysis/malware_07a.png)

Virustotal also finds the VBA code and detect the code page as Cyrillic.

![malware_07c](/images/malware_analysis/malware_07c.png)

I rescanned the file, and the number of AV solutions that detect the malware, at the time I'm writing this, is now 38.

![malware_07d](/images/malware_analysis/malware_07d.png)

Then, I changed only the modification timestamp of the document (added a title, saved, then removed title), effectivly also changing the hash.

![malware_07w](/images/malware_analysis/malware_07w.png)
![malware_07x](/images/malware_analysis/malware_07x.png)

And now only 19 AV solutions sucessfully detect it. This goes to show how ineffective many AV programs are. With a simple modification the malware author can cut the detection rate in half!

![malware_07y](/images/malware_analysis/malware_07y.png)

Below is the full list of AV programs that successfully detect it after the timestamp modification. I'm actually surprised that ESET and Bitdfender are not on the list.

![malware_07z](/images/malware_analysis/malware_07z.png)

## <a name="sandbox"></a> Sandbox

The sandbox analysis at malwr.com is shown below. You can see the original filename and the hashes.

![malware_06](/images/malware_analysis/malware_06.png)

The malware connects to several domains and IP addresses. It probably uses *api.ipfy.org*{: style="color: LightSalmon"} and *checkip.dyndns.org*{: style="color: LightSalmon"} to find the public IP address of the infected machine. The rest are likely C2 domains.

![malware_09](/images/malware_analysis/malware_09.png)

It also spawns several processes:

![malware_10](/images/malware_analysis/malware_10.png)

Sends 18 HTTP requests.

![malware_11](/images/malware_analysis/malware_11.png)

Screenshot of the opened document. 

![malware_08](/images/malware_analysis/malware_08.png)

## <a name="vm_detonation"></a> VM detonation

To gather more information, I also ran it in my VM (although it won't be any different from the results at malwr.com). 

![malware_12](/images/malware_analysis/malware_12.png)

On my VM it creates only one process - *svchost.exe*{: style="color: LightGreen"}. You'll see later why.
Checking the strings of *svchost.exe*{: style="color: LightGreen"}, with [Process Hacker](http://processhacker.sourceforge.net/), shows interesting domains. Some of them (the russian ones) weren't shown in the mawlr.com analysis.

![malware_13](/images/malware_analysis/malware_13.png)
![malware_14](/images/malware_analysis/malware_14.png)
![malware_15](/images/malware_analysis/malware_15.png)
![malware_16](/images/malware_analysis/malware_16.png)

The trace from [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) doesn't show anything I don't know already. The malware starts a new *svchost.exe*{: style="color: LightGreen"} process and the new process tries to connect to some IP addresses.

![malware_17](/images/malware_analysis/malware_17.png)
![malware_18](/images/malware_analysis/malware_18.png)
![malware_19](/images/malware_analysis/malware_19.png)

[API monitor](http://www.rohitab.com/apimonitor) shows that the Word process allocates memory with *NtAllocateVirtualMemory*{: style="color: LightGreen"} and RWX permissions, then writes 5883 bytes with *NtWriteVirtualMemory*{: style="color: LightGreen"} and after that calls *CreateTimerQueueTimer*{: style="color: LightGreen"} which can execute code and one of its arguments is an address that points inside the previously written memory.

![malware_20](/images/malware_analysis/malware_20.png)

One of the things *svchost.exe*{: style="color: LightGreen"} probably does is process enumeration. You can see that it iterates through all processes.

![malware_21](/images/malware_analysis/malware_21.png)
![malware_22](/images/malware_analysis/malware_22.png)

[TcpLogView](http://www.nirsoft.net/utils/tcp_log_view.html) logs only one connection.

![malware_25](/images/malware_analysis/malware_25.png)

With Wireshark you can see why. One of the Command and Control domains doesn't exist anymore, the other two resolve sucessfully, but the servers are down. This means I won't be able to analyse the other modules of the malware, but only the dropper.

![malware_26](/images/malware_analysis/malware_26.png)
![malware_27](/images/malware_analysis/malware_27.png)
![malware_28](/images/malware_analysis/malware_28.png)

# Static analysis (MS Word document)

The VBA script is heavily obfuscated, so I'll go directly to dynamic analysis. I thank the IT gods, that the VBA script editor has a debugger.

# <a name="dynamic_analysis_doc"></a> Dynamic analysis (MS Word document)

The VBA script loads some functions from several DLLs. The only one that can spawn a process is *CreateTimerQueueTimer*{: style="color: LightGreen"} which you saw earlier in the output from [API monitor](http://www.rohitab.com/apimonitor). I could stop the execution right before calling it and dump the memory contents that are going to be executed, but I need to know where the buffer starts and how big it is.

On the screenshot below, between the lines of code are the lyrics of the song Hurricane by Luke Combs written as comments.

![malware_29](/images/malware_analysis/malware_29.png)

The function *Document_Open()*{: style="color: LightGreen"} is automatically executed when the document is opened (if the macros are enabled). This function calls another one called *abraham()*{: style="color: LightGreen"}.

I renamed *Document_Open()*{: style="color: LightGreen"} to *Disabled_Document_Open()*{: style="color: LightGreen"}, to prevent the automatic execution every time I open the document.

![malware_30](/images/malware_analysis/malware_30.png)

Stepping through the code with the debugger, I found where the large string, that [olevba](https://www.decalage.info/python/oletools) showed, is loaded.

![malware_31](/images/malware_analysis/malware_31.png)

The *Right*{: style="color: LightGreen"} function removes the 4 leading spaces.

The next line decodes the string to binary format. I added a function to convert the bytes of the decoded string to hex and print it, then used a hex editor attached to the process to find the location and contents of the buffer holding the decoded string.

Note: My function omits leading zeros in the hex output (08 is printed as 8)... my knowledge of VBA is poor.

I don't know if this is the final transformation of the buffer so I'll still not dump it. I'll have to go all the way until *CreateTimerQueueTimer*{: style="color: LightGreen"} is called

![malware_32](/images/malware_analysis/malware_32.png)

Buffer that holds the decoded bytes is passed to the function *arch*{: style="color: LightGreen"} . Before continuing the analysis of *arch*{: style="color: LightGreen"} I'll first analyse the functions that it uses.

![malware_33](/images/malware_analysis/malware_33.png)

The function *birmingham*{: style="color: LightGreen"} is an alias for *NtWriteVirtualMemory*{: style="color: LightGreen"}.

![malware_34](/images/malware_analysis/malware_34.png)

*birmingham*{: style="color: LightGreen"} (*NtWriteVirtualMemory*{: style="color: LightGreen"}) is called from *policeman*{: style="color: LightGreen"}. If you follow the arguments, you can see that the first one (*kola*{: style="color: LightSalmon"}) is pointer to the address where data is going to be written. The second argument (*haft*{: style="color: LightSalmon"}) is pointer to a buffer that contains the data to be written and the third (*restrengthen*{: style="color: LightSalmon"}) is the number of bytes to write. So *policeman*{: style="color: LightGreen"} is just a wrapper for *NtWriteVirtualMemory*{: style="color: LightGreen"}

![malware_35](/images/malware_analysis/malware_35.png)
![malware_36](/images/malware_analysis/malware_36.png)

Now let's return to *arch*{: style="color: LightGreen"}. *arch*{: style="color: LightGreen"} accepts our decoded bytes as an argument. First it calls *policeman*{: style="color: LightGreen"} to store a pointer (4 bytes in size) to the argument (the buffer) in the variable *militarized*{: style="color: LightSalmon"}.

![malware_37](/images/malware_analysis/malware_37.png)

Below you can see that *militarized*{: style="color: LightSalmon"} (*accusation*{: style="color: LightSalmon"} is a pointer to it) holds an address, which points the buffer. 

![malware_38](/images/malware_analysis/malware_38.png)

The address if reversed because of the endianness.

![malware_39](/images/malware_analysis/malware_39.png)

Then, *arch*{: style="color: LightGreen"} uses *NtAllocateVirtualMemory*{: style="color: LightGreen"} to allocate 9593 bytes with Read,Write and Execute permissions. The *bowing*{: style="color: LightSalmon"} variable stores the pointer to that memory

![malware_40](/images/malware_analysis/malware_40.png)
![malware_41](/images/malware_analysis/malware_41.png)

Again *policeman*{: style="color: LightGreen"} (*NtWriteVirtualMemory*{: style="color: LightGreen"}) is called and 5883 bytes from the buffer are written to the newly allocated memory. 

Finally *arch*{: style="color: LightGreen"} returns a pointer to the executable memory that now holds the bytes of the decoded string.

![malware_42](/images/malware_analysis/malware_42.png)

Below you can see that *arch*{: style="color: LightGreen"} indeed returns a pointer to memory that holds the buffer, and stores it in the variable *humbler*{: style="color: LightSalmon"}.

![malware_43](/images/malware_analysis/malware_43.png)

A few lines later it calls the function *windzors*{: style="color: LightGreen"}, which takes 3 arguments, one of which is a pointer to a memory inside the buffer at an offset of 0x1090 bytes from the beginning.

![malware_44](/images/malware_analysis/malware_44.png)

*windzors*{: style="color: LightGreen"} calls *quartertone*{: style="color: LightGreen"} which is an alias for *CreateTimerQueueTimer*{: style="color: LightGreen"}. [MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682485(v=vs.85).aspx) tells us that  
*CreateTimerQueueTimer*{: style="color: LightGreen"} "Creates a timer-queue timer." and "When the timer expires, the callback function is called.".

The third argument is a pointer to the callback function and it is the same one which point inside the buffer with decoded bytes.

![malware_45](/images/malware_analysis/malware_45.png)

What's left is to dump 5883 bytes from the beginning of the buffer (the whole buffer). For the purpose I use [HxD](https://mh-nexus.de/en/hxd/) hex editor, attach it to the word process, locate the memory of the buffer, copy it and save it to a new file, that I called *shellcode.bin*{: style="color: LightSalmon"}.

![malware_46](/images/malware_analysis/malware_46.png)

So in summary, this stage of the malware decodes, injects and executes shellcode in its own process. 

# <a name="static_analysis_shellcode"></a> Static analysis (shellcode)

I open the *shellcode.bin*{: style="color: LightSalmon"} in IDA and tell IDA to treat address 0x1090 as a function.

![malware_47](/images/malware_analysis/malware_47.png)

With its first few instructions, the shellcode locates the base address of the first loaded module (DLL) in the process, which is *ntdll.dll*{: style="color: LightSalmon"}. Then it calls *find_function*{: style="color: LightGreen"} (you'll see why I called it that way) with a 4 byte value as an argument.

![malware_48](/images/malware_analysis/malware_48.png)

Before I explain the purpose of *find_function*{: style="color: LightGreen"}, I'll analyse the functions it uses. The first one is *get_pointer_to_PE_signature*{: style="color: LightGreen"}. It takes *eax*{: style="color: LightGreen"} as argument, which points to the base address of the DLL passed to *find_function*{: style="color: LightGreen"} and returns a pointer to the PE signaturem, which is at constant offset (0x3c bytes) from the beginning of the file.

![malware_52](/images/malware_analysis/malware_52.png)

*get_pointer_to_PE_signature*{: style="color: LightGreen"} is called from *get_export_table*{: style="color: LightGreen"}. This functions uses the pointer to the PE signature to find the address of the Export Table. 

![malware_51](/images/malware_analysis/malware_51.png)

Now you can see *find_function*{: style="color: LightGreen"} below. It iterates through the functions of the DLL, calcules a value (hash) based on their name, and compares it to the 4 byte value that was passed as an argument. If the values match, a pointer to that function is returned.

![malware_49](/images/malware_analysis/malware_49.png)
![malware_50](/images/malware_analysis/malware_50.png)

On the screenshot below is the hashing function.

![malware_53](/images/malware_analysis/malware_53.png)

All functions that are used by the shellcode are hashed and dynamically resolved with *find_function*{: style="color: LightGreen"}. 

I wrote a simple python script to decode all the hashes in the shellcode.

```python
# 'DLLstrings.txt' is generated with "strings -a *.dll" 
# from the system directory 
# which is SysWow64 on 64bit system or System32 on 32bit system.

file = open('DLLstrings.txt','r').read().split('\n')

def hash(s):
	eax = 0
	for i in range(len(s)):
		esi = eax
		eax = eax << 7
		eax = 0xffffffff & eax
		esi = esi >> 0x18
		esi = eax | esi
		if (0x80 & s[i]):
			eax = 0xffffff00 | s[i]
		else:
			eax = s[i]
		eax = eax ^ esi
	return eax

input_hash = raw_input("Enter hash value: ").lower()

for function_name in file:
	hashed_name = hex( hash( bytearray(function_name) ) )
	if hashed_name.find(input_hash) != -1:
		print('Success! The function is:\n')
		print(function_name)
		break
```

Example output:

![malware_57](/images/malware_analysis/malware_57.png)

*LdrLoadDLL*{: style="color: LightGreen"} is used to load other libraries.

![malware_54](/images/malware_analysis/malware_54.png)

Some of the functions it loads are typical for the process injection technique called "process hollowing",
which steps are:  

1) Start a new and legitimate process in suspended state.  
2) Save the context of the remote process with *GetThreadContext*{: style="color: LightGreen"}  
3) Unmap the memory of the remote process starting from the base address with *UnmapViewOfSection*{: style="color: LightGreen"}  
4) Allocate memory with RWX permission in the remote process, replacing the unmapped memory.  
5) Write the malicious code in the remote process at the allocated memory.  
6) Set the context to the one that was saved earlier.  
7) Resume execution with *ResumeThread*{: style="color: LightGreen"}.   

After these steps the code of the legitimate process is replaced with a malicious one, but the context is preserved and it will continue to look like a legitimate process (doing some bad things, though). 

![malware_55](/images/malware_analysis/malware_55.png)
![malware_56](/images/malware_analysis/malware_56.png)

The screenshots below shows that the malware does exactly the steps for process hollowing. I didn't show it but the shellcode decodes part of it's memory and loads it in a buffer, that's going to be injected in a remote process.

The process to be used for injection is.... *svchost.exe*{: style="color: LightGreen"} (surprise, surprise).

The base address of the remote process is 0x400000.

![malware_58](/images/malware_analysis/malware_58.png)

The memory to allocate in *svchost.exe*{: style="color: LightGreen"} is *SizeOfImage*{: style="color: LightSalmon"} bytes (this value is taken from the PE headers of the buffer, holding the already decoded malicous code, which appears to be a PE executable). The allocation starts from the base address of the remote process.

![malware_59](/images/malware_analysis/malware_59.png)

After the PE Headers are written, the shellcode loops through the sections of the malicous code, and writes them at the appropriate addresses in *svchost.exe*{: style="color: LightGreen"}.

![malware_60](/images/malware_analysis/malware_60.png)

And finally the now malicous *svchost.exe*{: style="color: LightGreen"} resumes execution.

![malware_61](/images/malware_analysis/malware_61.png)

## <a name="dump_svchost1"></a> Dumping the memory

To dump the injected code, I have to break right before it executes (before *ResumeThread*{: style="color: LightGreen"}). I use [x64dbg](https://x64dbg.com) for debugging and attach it to the MS Word process. Because I disabled the automatic execution of the VBA script, the malware won't start until I manually execute the script.

![malware_62](/images/malware_analysis/malware_62.png)

Set a breakpoint at *SetThreadContext*{: style="color: LightGreen"} function. It's unlikely that MS Word uses this function, so I'm sure the only place where a breakpoint will be hit is in the shellcode.

![malware_63](/images/malware_analysis/malware_63.png)

Running the VBA macro and immediately the breakpoint is hit.

![malware_64](/images/malware_analysis/malware_64.png)

With [Process Hacker](http://processhacker.sourceforge.net/) you can see that *svchost.exe*{: style="color: LightGreen"} is still in a suspended state (it's highlighted in gray). I also use it to dump the memory region at 0x400000, where the malicious code resides.

![malware_65](/images/malware_analysis/malware_65.png)
![malware_66](/images/malware_analysis/malware_66.png)

The sections of an executable file are mapped at different offsets from the beginning of the file, depending if it's loaded in memory or it's staying on disk. To be able to run the dumped code, I have to unmap it, using the tool [pe_unmapper](https://github.com/hasherezade/malware_analysis/tree/master/pe_unmapper).

![malware_67](/images/malware_analysis/malware_67.png)

And now to load it in IDA :)

To my surprize it has very few functions. Maybe there is yet another stage?

![malware_68](/images/malware_analysis/malware_68.png)

# <a name="static_analysis_svchost"></a> Static analysis (svchost.exe)

Below you can see where the last call in the *start*{: style="color: LightGreen"} function leads. These instructions look like gibberish. My bet is that this code is encrypted or packed.

![malware_69](/images/malware_analysis/malware_69.png)

After I reversed the functions, my suspicion was right. It gets a pointer to its own base address with *get_pointer_to_MZ_signature*{: style="color: LightGreen"}, loads different libraries and functions (similar to the way the shellcode did, but without the use of hashes) and then decrypts the memory to which the last call jumps.

![malware_70](/images/malware_analysis/malware_70.png)

The memory is decrypted with 0x59 as key.

![malware_70a](/images/malware_analysis/malware_70a.png)

## <a name="dump_svchost2"></a> Dump decrypted svchost.exe

To dump the fully decrypted binary, I'll again use a debugger. If you can't see the screenshots well, open them in a new tab.

![malware_71](/images/malware_analysis/malware_71.png)

I set the permissions of the .text section to RWX, so the code can modify (decrypt) itself.

![malware_72](/images/malware_analysis/malware_72.png)

There is a check right before the decryption routine that fails and I don't know why, but I manually bypass it, by changing the value of the Zero Flag.

![malware_73](/images/malware_analysis/malware_73.png)
![malware_74](/images/malware_analysis/malware_74.png)

When I reach the last call in the *start*{: style="color: LightGreen"} function, the code should be fully decrypted and I can use [Process Hacker](http://processhacker.sourceforge.net/) again to dump the memory.

![malware_75](/images/malware_analysis/malware_75.png)

Unmap the file.

![malware_76](/images/malware_analysis/malware_76.png)

Aaaaand now it looks better. As you can see there are many functions now.

![malware_77](/images/malware_analysis/malware_77.png)

The stages of the malware until now can be summarised in the following steps:

1) The word document decodes a large shellcode  
2) Then injects and executes the shellcode in its own process  
3) The shellcode decodes a buffer that is a malicious PE executable  
4) Injects the malicious code in a remote process (*svchost.exe*{: style="color: LightGreen"} ) via process hollowing  
5) The code of the new process is almost entirely encrypted, so it decrypts itself.  

# <a name="static_dynamic_analysis_svchost"></a> Static and Dynamic analysis (decrypted svchost.exe)

The call graph looks really big and it's going to take me a lot of time to reverse the whole binary. That's why I'll only analyse parts of it, like those used for networking stuff.

![malware_78](/images/malware_analysis/malware_78.png)

Below you can see the imported functions. There are no surprizes here, considering that we already knew that it connects to remote hosts, downloads files and executes them.
  
![malware_81](/images/malware_analysis/malware_81.png)
![malware_82](/images/malware_analysis/malware_82.png)

Some strings that I missed in the beginning of the analysis are HTTP Request headers and two format strings.

![malware_79](/images/malware_analysis/malware_79.png)  
![malware_80](/images/malware_analysis/malware_80.png)

The main function is an endless loop.

![malware_83](/images/malware_analysis/malware_83.png)

At the beginning of the loop, the first thing this stage of the malware does is to communicate with the C2 servers.

![malware_84](/images/malware_analysis/malware_84.png)

This function, collects information such as:
- OS Version
- MAC address
- Volume Serial Number of the C: drive
- Public IP address (by using *api.ipfy.org*{: style="color: LightSalmon"}
- Hostname and the domain

MAC address and the volume serial number are used to uniquely identify the machine.

The hostname and the domain are retrieved with the WinAPI function *LookupAccountSid*{: style="color: LightGreen"}, which
"accepts a security identifier (SID) as input. It retrieves the name of the account for this SID and the name of the first domain on which this SID is found.". The SID is taken from the *explorer.exe*{: style="color: LightGreen"} process, and to find *explorer.exe*{: style="color: LightGreen"} the malware iterates through the running processes
(do you remember the output of [API monitor](http://www.rohitab.com/apimonitor)? This is what I thought was process enumeration). 

![malware_90](/images/malware_analysis/malware_90.png)

Then it decrypts RC4 encrypted string, that holds the malware build version and the list of C2 domains separated by the pipe \| symbol.

The malware tries to connect to the first C2 domain and if successful sends the collected information in a HTTP POST request. If the connection fails it tries the next server in the list.

![malware_86](/images/malware_analysis/malware_86.png)  
![malware_85](/images/malware_analysis/malware_85.png)

Because the C2 servers are down (for this build at least) I spoofed the DNS response to point to my machine.

![malware_88](/images/malware_analysis/malware_88.png)  
![malware_89](/images/malware_analysis/malware_89.png)

You can see all the information it sends in the body of the HTTP POST request.

![malware_87](/images/malware_analysis/malware_87.png)

It also expects an answer (a command), which I think is encoded, I haven't reversed that part, because it's harder when I don't know how the response should look like.

Anyway, after the command is decoded, it enters a switch statement with several cases. Depending on the command it can:
- Download a file (in memory) and execute/inject it via process hollowing (again using *svchost.exe*{: style="color: LightGreen"})
- Download a DLL (in memory), load it, and call some function from it or start a new thread.
- Download a file to the %TEMP% directory and execute it.

![malware_91](/images/malware_analysis/malware_91.png)

# <a name="yara_rule"></a> Yara Rule

The encoded shellcode, in the word document, is stored in a tab which is part of a form and starts with 4 spaces. This format is uniqe and for some reason I don't think it'll change across versions. The shellcode is encoded as long contiuous string (7000+ characters), which are rare, but embedded in a tab even more. That's why I think this is a good thing to use to detect this malware. Of course combined with the function names "NtWriteVirtualMemory", "NtAllocateVirtualMemory" and "CreateTimerQueueTimer" which should be very rare in a legitimate word document.

![malware_92](/images/malware_analysis/malware_92.png)

```
rule trojan_downloader
{
	meta:
		description = "Detects MS Office document with embedded VBA trojan dropper"
		author = "Iliya Dafchev idafchev [4t] mail [dot] bg"
		date = "2017-09-21"

	strings:
		$ole_file_signature = { D0 CF 11 E0 A1 B1 1A E1 }

		$function1 = "CreateTimerQueueTimer"
		$function2 = "NtWriteVirtualMemory"
		$function3 = "NtAllocateVirtualMemory"

		$vba_project = "VBA_PROJECT" wide

		// match the encoded shellcode, inserted in a Tab
		// format: Tab<number> <size[4k-10k]> 0x00 0x80 <four_spaces> <at_least_15_printable_characters>
		$encoded_shellcode = /Tab\d[\x00-\xff][\x0f-\x27]\x00\x80\x20{4}[\x21-\x7e]{15}/

	condition:
		$ole_file_signature at 0 and all of ($function1, $function2, $function3, $vba_project) and $encoded_shellcode in (100000..filesize) and filesize > 100KB and filesize < 1MB
}
```
![malware_93](/images/malware_analysis/malware_93.png)

# <a name="snort_rule"></a> Snort rule

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Trojan installed on internal network!"; content:"/ls5/forum.php"; nocase; pcre:"/setedranty.com|attotperat.ru|robtetoftwas.ru/i"; pcre:"/GUID=\d+&BUILD=\d+&INFO=\N+&IP=\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}&TYPE=\d&WIN=\N+/i"; sid:1;)
```

# <a name="ioc"></a> Indicators of Compromise

The dropper isn't writing anything to disk (unless instructed by the hackers), so besides hashes there isn't anything else.
