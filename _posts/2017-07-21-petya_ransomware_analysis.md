---
layout: post
date:   2017-07-21 09:12:01 -0600
categories: writeup
description: "Analysis of the Petya/NotPetya ransomware."
title:  "Petya/NotPetya Ransomware Analysis"
---

I got the sample from [theZoo](https://github.com/ytisf/theZoo). I don't know if this is an actual sample caught "in the wild", but for my surprise it wasn't packed or had any advanced anti-RE tricks. I guess ransomware writers just want a quick profit. 

When I started the analysis (a few weeks ago), I didn't know much about how Petya works, so this whole analysis is my own. Probably I've got some things wrong, it's my first malware analysis and I'm doing it as a learning experience.

These resources helped me alot while doing the analysis:  
1. [Windows Functions in Malware Analysis – Cheat Sheet – Part 1](http://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/)

2. [Windows Functions in Malware Analysis – Cheat Sheet – Part 2](http://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/) 

3. [Practical Malware Analysis](https://www.nostarch.com/malware) 

4. [MSDN](https://msdn.microsoft.com/en-us/library)

The [Intel 64 and IA-32 architectures manual Volume 2](https://software.intel.com/en-us/articles/intel-sdm#three-volume) is also very handy when doing RE.

I've taken the necessary precautions:
- It's run in a virtual machine without network access, shared folders, shared clipboard or attached drives. It's completely isolated.
- The host machine uses different OS (Linux) than the guest (Windows), to minimize the risk of VM escape.
- The host machine is also without network access, to further minimize the risk of infecting other devices on my network.

Ok, let's begin!

# Triage analysis
### Checking strings
First I used [bintext](https://www.mcafee.com/us/downloads/free-tools/bintext.aspx) to list the strings in the file. Below is some portion of the interesting ones:

```
\\.\PhysicalDrive
1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX
IsWow64Process
GetExtendedTcpTable
\\.\C:
\\.\PhysicalDrive0
255.255.255.255
CreateFileA
WriteFile
ReadFile
GetSystemDirectoryA
DeviceIoControl
GetLogicalDrives
GetDriveTypeW
Sleep
CreateThread
GetTickCount
CreateProcessW
GetEnvironmentvariableW
ConnectNamedPipe
CreateNamedPipeW
LoadLibraryA
VirtualAlloc
CryptGenRandom
CryptExportKey
CryptEncrypt
CryptGenKey
CryptDestoryKey
InitiateSystemShutdownExW
CreateProcessAsUserW
DhcpEnumSubnets
DhcpEnumSubnetClients
NetServerEnum
AdjustTokenPrivileges
perfc.dat
MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB
C:\Windows;
.3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls.xlsx.xvd.zip.
Microsoft Enhanced RSA and AES Cryptographic Provider
README.TXT
\\.\pipe\%ws
TERMSRV/
127.0.0.1
SeTcbPrivilege
SeShutdownPrivilege
SeDebugPrivilege
C:\Windows\
\cmd.exe
wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D %c:
schtasks %ws/Create /SC once /TN "" /TR "%ws" /ST %02d:%02d
at %02d:%02d %ws
shutdown.exe /r /f
/RU "SYSTEM"
dllhost.dat
-d C:\Windows\System32\rundll32.exe "C:\Windows\%s",#1
wbem\wmic.exe
%s /node:"%ws" /user:"%ws" /password:"%ws"
process call create "C:\Windows\System32\rundll32.exe \"C:\Windows\%s\" #1
\\%s\admin$
\\%ws\admin$\%ws
```

So much useful output definitely means it's not packed!

### Checking the PE headers
Next I used PE Explorer and CFF Explorer to check what libraries it imports and what functions it exports. This also hinted that the binary probably isn't packed (many imported DLLs).

Imports:
```
kernel32.dll -> functions for working with files, processes, threads, memory...
user32.dll
advapi32.dll -> crypto functions
shell32.dll
ole32.dll
crypt32.dll -> crypto functions
shlwapi.dll -> functions for working with strings and filesystem paths
iphlpapi.dll
ws2_32.dll -> for setting up sockets
mpr.dll
netapi32.dll
dhcpsapi.dll
msvcrt.dll -> malloc, memset, free, rand
```

Exports:
```
perfc.1
```

The binary has four resources and the address of the entry point is at *0x10007D39*{: style="color: LightSalmon"}.

Well, from the imports and the strings output we can conclude that it can open, create, read and write files, it can encrypt and decrypt data, create processes and threads and access network resources, but we can't be sure that it actually does all of this. Also it probably uses cmd.exe, wevtutil, fsutil, schtasks, at, shutdown.exe, wmic.exe. To be sure we need to check the disassembly. 

This preliminary step is to make a hypothesis of what the malicous file probably does, but we can't be sure that it uses those functions and tools until we analyse the disassembly.

# Static and Dynamic Analysis
I won't go through every function of the binary, this would take way too much time and this post would've been longer than it already is.

When I opened the ransomware in IDA, at the entry point *0x10007D39*{: style="color: LightSalmon"} was the function *DllEntryPoint*{: style="color: LightGreen"}, so although the extension of the file is .exe, I guess it is actually a DLL.

Which means that the only thing that gets called from that DLL is the only export - *perfc.1*{: style="color: LightGreen"}. From there I'll start my analysis.

# Elevate Privileges

*prfc*{: style="color: LightGreen"} is a loong function, which calls lots of other funcions. The first one I'll call *ElevatePrivileges*{: style="color: LightGreen"} which calls another function (I'll call it *Fx*{: style="color: LightGreen"} for now ) 3 times with 3 different arguments.

```python
Fx(SeShutdownPrivilege)  
Fx(SeDebugPrivilege)  
Fx(SeTcbPrivilege)
```

Part of *Fx*{: style="color: LightGreen"} is shown below:  
![petya_000](/images/petya/petya_000.png)

The *AdjustTokenPrivileges*{: style="color: LightGreen"} function enables (or disables) access privileges. Malware uses it to gain additional permissions.
So I'll rename *Fx*{: style="color: LightGreen"} to *SetPrivileges*{: style="color: LightGreen"}. And now *ElevatePricileges*{: style="color: LightGreen"} looks like this:  
![petya_001](/images/petya/petya_001.png)

*ElevatePrivileges*{: style="color: LightGreen"} begin with these calls:  
```python
Setrivileges(SeShutdownPrivilege)  
SetPrivileges(SeDebugPrivilege)  
SetPrivileges(SeTcbPrivilege) 
```

Checking MSDN...  
*SeTcbPrivilege*{: style="color: LightGreen"} - "Allows a process to authenticate like a user and thus gain access to the same resources as a user."  
*SeDebugPrivilege*{: style="color: LightGreen"} - "Allows the user to attach a debugger to any process. This privilege provides access to sensitive and critical OS components"  
*SeShutdownPrivilege*{: style="color: LightGreen"} - "Allows a user to shutdown the local computer"

The *SeDebugPrivilege*{: style="color: LightGreen"} could be used to gain access to a system process. Gaining this privilege is equivalent to gaining local System access. Normal accounts can't give themselves this privilege, only if the user is local administrator, otherwise this privilege is denied.

After every attempt to set the privileges a bitmask is set, which is stored in esi register. If *SeShutdownPrivilege*{: style="color: LightGreen"} is successful the LSB of esi is set to 1 (by incrementing it). If *SeDebugPrivilege*{: style="color: LightGreen"} is successful the second bit is set to one (10 or 01 = 11), and the same for *SeTcbPrivilege*{: style="color: LightGreen"}. Then esi is saved in the variable that I renamed to *privileges*{: style="color: LightGreen"}.

*privileges*{: style="color: LightGreen"} = 111 (7 decimal) means all privileges were sucessfuly set  
*privileges*{: style="color: LightGreen"} = 101 (5 decimal) means only *SeDebugPrivileges*{: style="color: LightGreen"} failed

# Process Enumeration

Continuing with *ElevatePricileges*{: style="color: LightGreen"}...  
![petya_002](/images/petya/petya_002.png)

As you can see there's a function I already called *ProcessEnumeration*{: style="color: LightGreen"}, and here is small part of the disassembly to see why:  
![petya_003](/images/petya/petya_003.png)
![petya_005](/images/petya/petya_005.png)

*CreateToolhelp32Snapshot*{: style="color: LightGreen"} - "used to create snapshots of processes, heaps, threads, and modules".  
*Process32First*{: style="color: LightGreen"}/*Process32Next*{: style="color: LightGreen"} - "used to begin enumerating processes from a previous call to *CreateToolhelp32Snapshot*{: style="color: LightGreen"}".

So it seems that the malware iterates through the processes, calculates something based on their name (I haven't reversed the algorithm) and the return value is either -1 or a  4 byte value depending if the process name matches certain criteria.

The *GetModuleFilename*{: style="color: LightGreen"} call in *ElevatePrivileges*{: style="color: LightGreen"} "returns the filename of a module that is loaded in the current process. Malware can use this function to modify or copy files in the currently running process."

I couldn't find the value of *Src*{: style="color: LightGreen"}, so I patched the file to "transform" it to exe, that way I could use a debugger.
In my case *Src*{: style="color: LightGreen"} is 0, so it tries to get it's own filename. Therefore for me pszPath will contain the string "*C:\Users\IEUser\Desktop\Ransomware.Petrwrap\027cc450ef5f8c5f653329641ec1fed9.exe*{: style="color: LightSalmon"}". I think *Src*{: style="color: LightGreen"} holds a handle or pointer to the process that called the *prfc*{: style="color: LightGreen"} function from the DLL. Because I'm not actually calling it but starting it as an executable, *Src*{: style="color: LightGreen"} holds null value. I'm not entirely sure about this, though.

If *ElevatePrivileges*{: style="color: LightGreen"} succeeds it calls another function which reads a file and loads it into memory, and if it fails - the function returns. In this case it loads it's own executable in the memory of the process.

# prfc
Continuing with *prfc*{: style="color: LightGreen"}(On the screenshot below *F1*{: style="color: LightGreen"} is actually *ElevatePrivileges*{: style="color: LightGreen"}, I'm just too lazy to make another screenshot)   
![petya_004](/images/petya/petya_004.png)

The *WSAStartup*{: style="color: LightGreen"} call initializes low-level network functionality. After that there are some functions that initialize critical sections. 

*InitializeCriticalSection*{: style="color: LightGreen"} - initialize critical section object. Threads of a single process can use a critical section object for mutual-exclusion synchronisation. Which means that parts of the code which use critical section calls are for thread synchronization. 

I'm going to skip *sub_10009590*{: style="color: LightGreen"} subroutine, beacause I'm not sure what it does.

The other subroutines in this screenshot aren't very interesting. Some functions for string comparisons and the last one checks for passed arguments.

From now on I won't explain in detail the process of how I analysed the functions, so in the screenshots that follow the functions will already be renamed. I'm only going to explain how they work and not how I came to the conclusion of how they work.

# Create file in WinDir
![petya_006](/images/petya/petya_006.png)

Next, If the ransomware has admin privileges (*SeDebugPrivilege*{: style="color: LightGreen"} was successful), it creates a file with the same name at *C:\Windows*{: style="color: LightSalmon"} directory  (in my case that files is "*C:\Windows\027cc450ef5f8c5f653329641ec1fed9.exe*{: style="color: LightSalmon"}")

![petya_007](/images/petya/petya_007.png)

Also the file is actually empty, nothing gets ever written to it (the handle is lost, but left open). I don't know why it does that, my guess is it tries to check if it has write access to the Windows directory. And if a file with the same name already exists the process terminates. 

After that it destroys the MBR.  

# Destroy MBR  
![petya_008](/images/petya/petya_008.png)

It opens the C volume with *GENERIC_WRITE*{: style="color: LightSalmon"} (*0x40000000*{: style="color: LightSalmon"}).
```c
CreateFileA('\\.\C:', 0x40000000, 3, 0, 3, 0, 0);
```

Next it calls:
```c
DeviceIoControl(hDevice, IoControlCode, lpInBuffer, InBufferSize, lpOutBuffer, OutBufferSize, lpBytesReturned, lpOverlapped);
// where
IoControlCode = 0x70000
OutBufferSize = 0x18
lpInBuffer = 0
InBufferSize = 0
lpOverlapped = 0
```
The *DeviceIoControl*{: style="color: LightGreen"}  function "sends a control code directly to a specified device driver, causing the corresponding device to perform the corresponding operation" and the operation to be performed is specified by IoControlCode.

*0x70000*{: style="color: LightSalmon"} is the *IOCTL_DISK_GET_DRIVE_GEOMETRY*{: style="color: LightSalmon"} control code, which "retrieves information about the physical disk's geometry: type, number of cylinders, tracks per cylinder, sectors per track and bytes per sector".

Then the malware allocates a fixed memory from the heap with
```c
LocalAlloc(flags=0, Bytes);
```

To find how many bytes it allocates I used a debugger again and found that *[esp+28h+lDistanceToMove]*{: style="color: LightGreen"} points to that part of of *OutBuffer*{: style="color: LightGreen"} which holds the bytes per sector (0x200 = 512 bytes). This value is multiplied by 0xA, so 0x1400 (5120 decimal) bytes are allocated.

![petya_009](/images/petya/petya_009.png)

The file pointer is set at 512 bytes from the beginning of the C volume, and the next 512 bytes (the second sector) are overwritten with data from our allocated memory. This operation corrupts the [PBR](http://glennastory.net/boot/pbr.html).

After that the ransomware overwrites the MBR.  

![petya_010](/images/petya/petya_010.png)

*OverwriteMBR*{: style="color: LightGreen"} function is way too big to explain all of it here. Basically it opens the first physical drive with:
```c
CreateFileA('\\.\PhysicalDrive0', 0x80100000, 3, 0, 3, 0, 0);
```

Then it overwrites the first 19 sectors of the physical drive with data from a large buffer (9728 bytes).  

![petya_011](/images/petya/petya_011.png)

*WriteToFile*{: style="color: LightGreen"} function uses the value in *eax*{: style="color: LightGreen"} as an argument. That value is then stored in *esi*{: style="color: LightGreen"}.  

![petya_012](/images/petya/petya_012.png)

As you can see *esi*{: style="color: LightGreen"} gets left shifted by 9 which is equivalent to N times 512.  
1 \<< 9 = 512  
2 \<< 9 = 1024  
This value is then used to set the file pointer at the beginning of the selected sector.

Next, sectors 32, 33 and 34 are overwritten.

![petya_013](/images/petya/petya_013.png)

If any of the *WriteToFile*{: style="color: LightGreen"} functions fail, then after *OverwriteMBR*{: style="color: LightGreen"} completes *OverwriteWithLocalAlloc*{: style="color: LightGreen"} is called which overwrites the first 10 sectors.

The ransomware wipes the MBR and some sectors after it. No information is saved/encrypted for restoring this data.

# prfc 
We are back to the export function *prfc*{: style="color: LightGreen"}. After the MBR wiping the malware sets a scheduled task for system shutdown.

![petya_014](/images/petya/petya_014.png)

# Create scheduled task to shutdown the system
It takes the current time and sets a scheduled task to run after 3 minutes by executing one of the following commands (depending on the Windows version):

```
C:/Windows/System32/cmd.exe /c schtasks /RU "SYSTEM" /Create /SC once /TN "" /TR " "C:/Windows/System32/shutdown.exe /r /f" /ST 16:03

C:/Windows/System32/cmd.exe /c at 16:03 C:\Windows\System32\shutdown.exe /r /f 
```

![petya_016](/images/petya/petya_016.png)

# Network enumeration
Then *prfc*{: style="color: LightGreen"} starts a new thread which executes network enumeration functions.

![petya_015](/images/petya/petya_015.png)

The *NetworkEnumeration*{: style="color: LightGreen"} function:  
![petya_017](/images/petya/petya_017.png)

First, it gets the name of the machine (in this case "*IE11WIN7*{: style="color: LightSalmon"}") using the function
*GetComputerNameExW*{: style="color: LightGreen"}.

Next, a new thread is started, which executes the *EnumerateSMB*{: style="color: LightGreen"} function.

# EnumerateSMB
This function uses *GetAdaptersInfo*{: style="color: LightGreen"} to get the IP address and subnetmask of all network interfaces.  
![petya_018](/images/petya/petya_018.png)

After that it checks if the machine is a server or a workstation.  
![petya_019](/images/petya/petya_019.png)

It does that with *NetServerGetInfo*{: style="color: LightGreen"}:
```c
NetServerGetInfo(servername, level, *bufptr);
//where
servername = 0;
level = 0x65; // 101 decimal
);
```  
From MSDN:  
level 101 - "Return the server name, type, and associated software. The bufptr parameter points to a SERVER_INFO_101 structure."
```c
typedef struct _SERVER_INFO_101 {
  DWORD  sv101_platform_id;
  LPWSTR sv101_name;
  DWORD  sv101_version_major;
  DWORD  sv101_version_minor;
  DWORD  sv101_type;
  LPWSTR sv101_comment;
} SERVER_INFO_101, *PSERVER_INFO_101, *LPSERVER_INFO_101;
```
Look at the disassembly:  
![petya_020](/images/petya/petya_020.png)

*ecx*{: style="color: LightGreen"} holds the value of *bufptr*{: style="color: LightGreen"} and then the value 0x10 (16) bytes after the beginning of the buffer is compared to 0x8000. If you look at the structure you'll see that value is the server type *sv101_type*{: style="color: LightGreen"}.

Server type *0x8000*{: style="color: LightSalmon"} (*SV_TYPE_SERVER_NT*{: style="color: LightSalmon"}) is "Any server that is not a domain controller." If this is the type of the server, the function returns 1.

If not, then it's compared to *0x18*{: style="color: LightSalmon"} which is composed of 0x8 \|\| 0x10.

*0x8*{: style="color: LightSalmon"} (*SV_TYPE_DOMAIN_CTRL*{: style="color: LightSalmon"}) - "A primary domain controller".  
*0x10*{: style="color: LightSalmon"} (*SV_TYPE_DOMAIN_BAKCTRL*{: style="color: LightSalmon"}) - "A backup domain controller".

This function returns 1 if the machine is any kind of server, and 0 if it's not.

If the machine is a server, the function *EnumDHCPSubnets*{: style="color: LightGreen"} is executed.  
![petya_021](/images/petya/petya_021.png)

This function checks if the server is a DHCP server, if it is then it gets the subnets and the IP addresses of the machines that have leases. To accomplish this, it makes use of *DhcpEnumSubnets*{: style="color: LightGreen"}, *DhcpGetSubnetInfo*{: style="color: LightGreen"} and *DhcpEnumSubnetClients*{: style="color: LightGreen"} functions.

After that a new thread is started, which scans the whole networks that were found for ports 445 (SMB) and 139 (NetBIOS).  
![petya_022](/images/petya/petya_022.png)

The *ScanSMB*{: style="color: LightGreen"} iterates through every IP address in the network (from the network address to the broadcast address) and tries to establish a TCP connection on the SMB port and if it fails - on NetBIOS port. 

![petya_023](/images/petya/petya_023.png)

That's the end of *EnumerateSMB*{: style="color: LightGreen"}. Let's return to the other network enumerations..

# GetTcpConnections
This function gets the TCP connections of the local machine. It loads *iphlpapi.dll*{: style="color: LightGreen"} library and uses the *GetExtendedTcpTable*{: style="color: LightGreen"} function. 

The information that's available is similar to the one you get with the *netstat*{: style="color: LightGreen"} command - local IP, local Port, remote IP, remote Port and status.

The ransomware only saves the remote addresses of the TCP connections.

# GetLocalNetworkIPs
This function enumerates the IP addresses from the ARP cache with the *GetIpNetTable*{: style="color: LightGreen"} call.

# EnumerateMachines
Enumerates the machine in the domain.  
![petya_037](/images/petya/petya_037.png)

Uses the *NetServerEnum*{: style="color: LightGreen"} function, which "lists all servers of the specified type that are visible in a domain".  
![petya_038](/images/petya/petya_038.png)

The *level*{: style="color: LightGreen"} parameter indicates "the information level of the data requested." When its value is 101, *NetServerEnum*{: style="color: LightGreen"} returns "server names, types, and associated data. The bufptr parameter points to an array of SERVER_INFO_101 structures".

```c
typedef struct _SERVER_INFO_101 {
  DWORD  sv101_platform_id;	// The information level to use for platform-specific information
  LPWSTR sv101_name;	// the name of a server
  DWORD  sv101_version_major;
  DWORD  sv101_version_minor;
  DWORD  sv101_type;	// The type of software the computer is running. 
  LPWSTR sv101_comment;
} SERVER_INFO_101, *PSERVER_INFO_101, *LPSERVER_INFO_101;
```

So the function is called with:  
*level*{: style="color: LightGreen"} = *101*{: style="color: LightSalmon"}  
*server type*{: style="color: LightGreen"} =  *0x80000000*{: style="color: LightSalmon"} (*SV_TYPE_DOMAIN_ENUM*{: style="color: LightSalmon"}) Which means it will return information about the domain.

In my case, I'm not on a domain, so the function returns the following values:  
*sv101_platform_id*{: style="color: LightGreen"} = *500*{: style="color: LightSalmon"} (*PLATFORM_ID_NT*{: style="color: LightSalmon"}) -> Windows NT platform  
*sv101_name*{: style="color: LightGreen"} = *WORKGROUP*{: style="color: LightSalmon"}  
*sv101_type*{: style="color: LightGreen"} = *0x80001000*{: style="color: LightSalmon"} (*SV_TYPE_DOMAIN_ENUM*{: style="color: LightSalmon"} \| *SV_TYPE_NT*{: style="color: LightSalmon"})  

Then it checks if the *server type*{: style="color: LightGreen"} is a domain (*0x80000000*{: style="color: LightSalmon"}), if it is, calls itself but with parameters (in my case):  
*domain*{: style="color: LightGreen"}  = *WORKGROUP*{: style="color: LightSalmon"}  (the name of the domain)  
*server type*{: style="color: LightGreen"}  = *3*{: style="color: LightSalmon"}  (*SV_TYPE_WORKSTATION*{: style="color: LightSalmon"}  \| *SV_TYPE_SERVER*{: style="color: LightSalmon"} ) which means this time it will return information about the machines (workstations and servers) on the domain.  
![petya_039](/images/petya/petya_039.png)

It checks it it's a Windows NT platform and if the major version is above 4, saves the machine name.

After all of this, the *NetworkEnumeration*{: style="color: LightGreen"} thread waits for 3 minutes and then scans again.

# Run resource 1 or 2
If the malware has admin privileges (*SeDebugPrivilege*{: style="color: LightGreen"}), then it runs the first or second resource.  
![petya_024](/images/petya/petya_024.png)

First, it checks if the process is running under WOW64 (the x86 emulator that allows 32-bit Windows applications to run on 64-bit Windows), that way it determines if it's in a 64bit or 32bit environment and loads different resources depending on that.
![petya_025](/images/petya/petya_025.png)

I extracted the resources under linux, using *binwalk*{: style="color: LightGreen"} on the ransomware to find their location in the file and then *dd*{: style="color: LightGreen"} to carve them out. They are zlib compressed, but with a small python script I decompressed them.

![petya_026](/images/petya/petya_026.png)

Carve out the resources:
```bash
dd if=027cc450ef5f8c5f653329641ec1fed9.exe of=rs1 bs=1 skip=105196 count=24960
dd if=027cc450ef5f8c5f653329641ec1fed9.exe of=rs2 bs=1 skip=130156 count=27428
dd if=027cc450ef5f8c5f653329641ec1fed9.exe of=rs3 bs=1 skip=157584 count=191608
dd if=027cc450ef5f8c5f653329641ec1fed9.exe of=rs4 bs=1 skip=349192 count=7317
```

The script to decompress:
```python
#!/usr/bin/env python3
import zlib

for i in range(1,5):
	in_filename = 'rs' + str(i)
	in_f = open(in_filename,'rb').read()
	d = zlib.decompress(in_f)

	out_filename = 'rs' + str(i) + '-decompressed'
	out_f = open(out_filename,'wb')
	out_f.write(d)
	out_f.close()
```

As you can see below, resource 1 is indeed a 32bit (resource 3 also) executable, and resource 2 - 64bit.  
![petya_027](/images/petya/petya_027.png)

Resource 4 didn't have any meaningful strings in it. When I opened it in hex editor there were parts with many repeating x86 bytes:  
![petya_028](/images/petya/petya_028.png)

In PE executable files the 0x00 byte is very frequent. And when the file is XOR encrypted with a single byte key, the 0x00 byte parts become equal to the key (0x00 xor 0x86 = 0x86). I thought that this resource is encrypted with 0x86 key and when I XORed it with 0x86, there were two meaningful strings in it:

![petya_029](/images/petya/petya_029.png)

So it does appear to be XOR encrypted. It still doesn't look as an executable file or any meaningful file for that matter, but I'll be dealing with it later.

Let's return to our *RunResource12*{: style="color: LightGreen"} function. After the WOW64 check the malware loads the appropriate resource (1 for 32bit and 2 for 64bit system) into memory and decompresses it. Then it creates a temporary file at "*C:\Users\\<username\>\AppData\Local\Temp\xxxx.tmp*{: style="color: LightSalmon"}" with a random name, using the *GetTempFileNameW*{: style="color: LightGreen"} function.

Then it creates a new GUID and writes the decompressed resource to the temporary file that it just created.  
![petya_030](/images/petya/petya_030.png)

Starts a thread (*ConnNamedPipe*{: style="color: LightGreen"}), that creates a Named Pipe server "*\\\\.\\pipe\\{GUID}*{: style="color: LightSalmon"}" and then executes the temporary file with an argument:
```
C:\Users\\<username\>\AppData\Local\Temp\xxxx.tmp \\.\pipe\{GUID}
```
![petya_031](/images/petya/petya_031.png)  
![petya_032](/images/petya/petya_032.png)

I guess the resource is the named pipe client, but I won't be analysing it now. At the end of the function the thread is closed and the temporary file gets deleted.

# Copy Resource 3
After resource 1 or 2, the third resource is loaded, decompressed and written to "*C:\Windows*{: style="color: LightSalmon"}" directory with filename "*dllhost.dat*{: style="color: LightSalmon"}".  
![petya_033](/images/petya/petya_033.png)

# admin$ share
At this point the malware tries to spread via the admin share.

![petya_034](/images/petya/petya_034.png)

It enumerates the network resources with *WNetOpenEnum*{: style="color: LightGreen"} function and arguments:  
*dwScope*{: style="color: LightGreen"} = 1 (*RESOURCE_CONNECTED*{: style="color: LightSalmon"}) - "Enumerate all currently connected resources"  
*dwType*{: style="color: LightGreen"} = 0 (*RESOURCETYPE_ANY*{: style="color: LightSalmon"}) - "All resources"  

Then it uses *WNetEnumResource*{: style="color: LightGreen"}, which "continues an enumeration of network resources that was started by a call to the WNetOpenEnum function." and saves the remote name of the machine that shares the resource.  
![petya_035](/images/petya/petya_035.png)

Then it enumerates the credentials for TERMSRV (remote desktop):  
![petya_036](/images/petya/petya_036.png)

And after that it tries to write itself to the admin shares of the machines with the credentials it found and executes with the following command:  
```
C:\Windows\System32\wbem\wmic.exe /node:\<node\> /user:\<username\> /password:\<password\> process call create "C:\Windows\System32\rundll32.exe \"C:\Windows\\<filename\>\""
```

# Exploit SMB
After it tries to spread via the admin share, it starts a thread which executes lots of other functions and one of them is this monster:  
![petya_044](/images/petya/petya_044.png)

I didn't even try to analyse it and started to look for other things in the binary. I was wondering about the fourth resource, and by following the cross references of the *FindResource*{: style="color: LightGreen"} function, I found where it was loaded (hint: in that monster function). I started debugging from where the resource was being loaded into memory.

![petya_040](/images/petya/petya_040.png)

Later the resource is XOR decrypted using 0x86 as key (as I was suspecting earlier).  
![petya_041](/images/petya/petya_041.png)

There were some other transformations of the resource after that, I was too lazy to reverse them. Also the 'monster function', at the beginning opens a TCP connection to port 445 (SMB).  
![petya_042](/images/petya/petya_042.png)

I continued debugging until I reached a socket send. The resource, after its decrypted is sent to port 445. I'm willing to bet that this is the eternal blue exploit. I dumped the memory and extracted the decrypted resource (yeah, I could've caught it with wireshark but that idea came too late :D) and loaded it in wireshark.

![petya_045](/images/petya/petya_045.png)

So I called the function in prfc *Exploit_EternalBlue*{: style="color: LightGreen"}:  
![petya_043](/images/petya/petya_043.png)

# Encrypt drives
Now the ransomware finally starts to encrypt.  
![petya_046](/images/petya/petya_046.png)

First, it iterates throught the drives *C:*{: style="color: LightSalmon"}, *D:*{: style="color: LightSalmon"}, ...   
![petya_047](/images/petya/petya_047.png)

Creates a thread that encrypts the current drive (that string you see there is the public key of the malware writers):  
![petya_048](/images/petya/petya_048.png)

Next, it generates 128bit AES key:  
![petya_050](/images/petya/petya_050.png)

And then, the function *EncryptFiles*{: style="color: LightGreen"} starts encrypting the files on the drive with the AES key. It encrypts only those files that match certain extensions.  
![petya_052](/images/petya/petya_052.png)

# RansomNote
The malware imports the public key and then encrypts the AES key with it.  
![petya_054](/images/petya/petya_054.png)

After that the ransom note is created. It's a text file called "*README.TXT*{: style="color: LightSalmon"}" and created at the root of the drive. It contains "*Installation ID*{: style="color: LightSalmon"}" which  is the encrypted AES key, which the victims should send to the cyber criminals to decrypt, after they pay the ransom.  
![petya_055](/images/petya/petya_055.png)

# Clear event logs
Back at *prfc*{: style="color: LightGreen"}... After the *EncryptDrives*{: style="color: LightGreen"} function the malware clears the event logs and the USN change journal ("which provides a persistent log of all changes made to files on the volume") with the command:  
```
wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn delete journal /D C:
```  
![petya_056](/images/petya/petya_056.png)

# TheEnd
Finally the ransomware shuts down the machine.  
![petya_057](/images/petya/petya_057.png)


# Petya/NotPetya functionallity summarized
```
Try to elevate privileges
If admin privileges
	then destroy the MBR (and 10 to 19 sectors after it)
Set scheduled task for system shutdown after 3 minutes
Enumerate SMB hosts, IP addresses and machines every 3 minutes
Create and execute temporary file (resource 1 or 2)
Create C:\Windows\dllhost.dat (resource 3)
Try to spread via admin share
Try to spread via EternalBlue exploit
Encrypt files with AES-128
Encrypt the AES key with the public key
Destroy AES key
Delete logs
Shutdown the system
```

Although this file didn't use anti-RE techniques it was still a great and challenging learning experience.
