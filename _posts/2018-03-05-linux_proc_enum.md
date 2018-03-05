---
layout: post
date:   2018-03-05 09:12:01 -0600
categories: enumeration
description: "When attackers have arbitrary file read access to a Linux machine, they can leverage the /proc filesystem for enumeration"
title:  "Linux enumeration with read access only"
---
# Table of contents
[Introduction](#introduction)  
[The proc filesystem](#proc)  
[Default paths of configuration files](#config_files)  

# <a name="introduction"></a> Introduction
If attackers exploit a vulnerability that gives them the ability to read arbitrary files from a remote system, they must count on default locations of configuration files to enumerate the system. They can't execute commands or list the files inside the directories and their permissions. 

An example of such attack is XML External Entity (XXE) vulnerability, which could lead to disclosure of local files. The example below shows XXE exploit to read /etc/passwd file.  
![xxe_vulnerability](/images/linux_proc_enum/xxe01.png)

But attackers can enumerate much more than just files, when they have file read access. By utilizing the /proc filesystem it's possible to list running processes, mounted filesystems, network connections, listening ports, ARP cache and other things without the ability to execute commands.

Below is an example of XXE exploit to list running processes without the need of command execution.  
![xxe_vulnerability](/images/linux_proc_enum/xxe02.png)

# <a name="proc"></a> The proc filesystem
The man pages explain the proc filesystem well enough: "*The proc filesystem is a pseudo-filesystem which provides an interface to kernel data structures. It is commonly mounted at /proc. [...] Most of the files in the proc filesystem are read-only, but some files are writable, allowing kernel variables to be changed.*". 

So the pseudo-files inside /proc represent data stored in and used by the kernel in real time. Some programs make use of the data available in /proc, make it more user-friendly and show the information to the user. One such program, which everyone knows, is top. You can easily verify this with strace:
```
root@kali:~# strace top
execve("/usr/bin/top", ["top"], 0x7ffd2d20a6e0 /* 44 vars */) = 0
[...snip...]

stat("/proc/9", {st_mode=S_IFDIR|0555, st_size=0, ...}) = 0
open("/proc/9/stat", O_RDONLY)          = 6
read(6, "9 (rcu_bh) S 2 0 0 0 -1 2129984 "..., 1024) = 148
close(6)                                = 0
open("/proc/9/statm", O_RDONLY)         = 6
read(6, "0 0 0 0 0 0 0\n", 1024)        = 14
close(6)                                = 0
open("/proc/9/status", O_RDONLY)        = 6

[...snip...]
```

Below are the files that would be useful to an attacker.

*/proc/net/arp*{: style="color: LightGreen"} - contains the ARP cache. Could be used to enumerate machines on the LAN.  
```
root@kali:~# cat /proc/net/arp 
IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         64:70:02:cd:47:3a     *        wlan0
```

*/proc/net/dev*{: style="color: LightGreen"} - contains network device status information and basic statistics. It's used by the ifconfig program. Could be used to enumerate network interfaces.
```
root@kali:~# cat /proc/net/dev
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
 wlan0: 21574215   26111    0    0    0     0          0         0  2779687   19557    0    0    0     0       0          0
  eth0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
    lo: 3576918    2567    0    0    0     0          0         0  3576918    2567    0    0    0     0       0          0
```

*/proc/net/route*{: style="color: LightGreen"} - contains the routing table. The IP addresses are in HEX format.
```
root@kali:~# cat /proc/net/route
Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT                                                       
wlan0   00000000        0100A8C0        0003    0       0       600     00000000        0       0       0                                                                            
wlan0   0000A8C0        00000000        0001    0       0       600     00FFFFFF        0       0       0                                             
```
              
*/proc/net/tcp*{: style="color: LightGreen"} - contains the TCP socket table. Can be used to enumerate network connections and listening ports. The uid field holds the effective UID of the creator of the socket. IP addresses and ports are shown in HEX format. If "rem_address" is null, "local_address" represents listening socket. In this case the machine listens on 0100007F:0FA0 (equal to 127.0.0.1:4000). Addresses are in little endian.
```
root@kali:~# cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:0FA0 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 39786 1 ffff8add4e388000 100 0 0 10 0                     
   1: 6400A8C0:DAAE 40706597:01BB 01 00000000:00000000 02:0000030C 00000000     0        0 84209 2 ffff8adcea1d8800 26 4 12 10 -1 
```

*/proc/net/tcp6*{: style="color: LightGreen"} - same as /proc/net/tcp, but for IPv6.

*/proc/net/udp*{: style="color: LightGreen"} - contains the UDP socket table.

*/proc/net/udp6*{: style="color: LightGreen"} - contains the UDP socket table for IPv6.

*/proc/net/wireless*{: style="color: LightGreen"} - contains wireless device information and basic statistics.
```
root@kali:~# cat /proc/net/wireless 
Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
 wlan0: 0000   68.  -42.  -256        0      0      0      0    208        0
```

*/proc/[pid]/cmdline*{: style="color: LightGreen"} - holds the complete command line for the process with the given PID. The arguments are separated by a null byte, that's why when printed they appear concatenated.
```
root@kali:~# python -m SimpleHTTPServer 8080 &
[2] 2837
root@kali:~# Serving HTTP on 0.0.0.0 port 8080 ...

root@kali:~# cat /proc/2837/cmdline 
python-mSimpleHTTPServer8080
```

It's possible to write a script to enumerate the processes on the system by reading */proc/[pid]/cmdline*{: style="color: LightGreen"} for a range of PIDs (for example from 1 to 30000 or more). Here's an example of such script, which enumerates processes through tftp:
```sh
#!/bin/bash

for i in {1..30000}
do
        tftp 192.168.0.1 2>&1 >/dev/null 2>/dev/null << EOF
        get /proc/$i/cmdline
        quit
        EOF
        if ! [ -z "$(cat cmdline)" ]; then
                cat cmdline && echo
        fi
done
```

And the result is:
```
/sbin/init
/lib/systemd/systemd-journald
vmware-vmblock-fuse/run/vmblock-fuse-orw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid

[...snip...]

/usr/sbin/vsftpd/etc/vsftpd.conf
/usr/sbin/cron-f
/usr/sbin/rsyslogd-n
/usr/sbin/sshd-D
/usr/sbin/squid-YC-f/etc/squid/squid.conf
(squid-1)-YC-f/etc/squid/squid.conf
(logfile-daemon)/var/log/squid/access.log
/usr/sbin/apache2-kstart
/usr/sbin/apache2-kstart

[...snip...]
```

*/proc/[pid]/status*{: style="color: LightGreen"} - holds information about the process name, state, PPID, UID, GID and supplementary group list. 
```
root@kali:~# cat /proc/2837/status
Name:   python
Umask:  0022
State:  S (sleeping)
Tgid:   2837
Ngid:   0
Pid:    2837
PPid:   2473
TracerPid:      0
Uid:    0       0       0       0
Gid:    0       0       0       0
FDSize: 256
Groups:  
[...snip...]
```

*/proc/[pid]/loginuid*{: style="color: LightGreen"} - The loginuid value is used to track what account a user gained system access with. All system entry point programs should set this value right before changing to the uid of the user granted access so that audit events are properly attributed to the that user.
```
root@kali:~# ssh test_user@localhost
test_user@localhost's password: 

$ cat /proc/self/loginuid
1000
$ cat /proc/2837/loginuid
0
```

*/proc/[pid]/comm*{: style="color: LightGreen"} - the command name associated with the process. Typically the process name. Different threads in the same process may have different comm values, accessible via */proc/[pid]/task/[tid]/comm*{: style="color: LightGreen"}.
```
root@kali:~# cat /proc/2837/comm
python
```

*/proc/[pid]/attr/current*{: style="color: LightGreen"} - contains the SELinux security context of a process.
```
root@kali:~# cat /proc/2837/attr/current 
unconfined
```

*/proc/[pid]/environ*{: style="color: LightGreen"} - contains the initial environment variables which were set when the currently executing program was started.

In all previous examples, "self" can be used instead of [pid], to use the current process PID.
```
root@kali:~# cat /proc/self/comm
cat
```

*/proc/partitions*{: style="color: LightGreen"} - enumerate the available partitions.
```
root@kali:~# cat /proc/partitions 
major minor  #blocks  name

   8        0  625131864 sda
   8        1     512000 sda1
   8        2  101888000 sda2
   8        3  215529472 sda3
   8        4          1 sda4
   8        5  233792442 sda5
   8        6   41942016 sda6
   8        7    1999872 sda7
   8        8   29464576 sda8
  11        0    1048575 sr0
```

*/proc/modules*{: style="color: LightGreen"} - list the loaded kernel modules.
```
root@kali:~# cat /proc/modules 
fuse 98304 5 - Live 0xffffffffc0c2c000
ctr 16384 4 - Live 0xffffffffc072d000
ccm 20480 6 - Live 0xffffffffc06f6000
pci_stub 16384 1 - Live 0xffffffffc06f1000
vboxpci 24576 0 - Live 0xffffffffc06e6000 (O)
[...snip...]
```

*/proc/mounts*{: style="color: LightGreen"} - holds the mounted filesystems.
```
root@kali:~# cat /proc/mounts 
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
[...snip...]
/dev/sda2 /mnt fuseblk rw,relatime,user_id=0,group_id=0,allow_other,blksize=4096 0 0
```

*/proc/sched_debug*{: style="color: LightGreen"} - Could be used to list the running processes on every CPU
```
root@kali:~# cat /proc/sched_debug
[...snip...]

runnable tasks:
            task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep
----------------------------------------------------------------------------------------------------------
    mm_percpu_wq     6        55.852300         2   100         0.000000         0.002146         0.000000 0 0 /
     ksoftirqd/0     7   1236364.953796      8587   120         0.000000       208.716001         0.000000 0 0 /
          rcu_bh     9        59.855652         2   120         0.000000         0.001254         0.000000 0 0 /
     migration/0    10         0.000000       124     0         0.000000         7.941575         0.000000 0 0 /
      watchdog/0    11         0.000000      2565     0         0.000000        33.640540         0.000000 0 0 /

[...snip...]

        rsyslogd   544   1152885.712609        46   120         0.000000        15.026057         0.000000 0 0 /
   rs:main Q:Reg   568   1147101.764004      4543   120         0.000000       178.167006         0.000000 0 0 /
  NetworkManager   573   1235783.020177      2888   120         0.000000      3033.867445         0.000000 0 0 /
           gdbus   625   1229055.325319      3619   120         0.000000       429.441316         0.000000 0 0 /
 iprt-VBoxTscThr   647   1225259.884033       170   120         0.000000         6.366787         0.000000 0 0 /
           gmain   657      3200.951729         7   120         0.000000         0.119794         0.000000 0 0 /
           gdbus   658   1104709.985140       190   120         0.000000        30.162614         0.000000 0 0 /
  wpa_supplicant   684   1235805.678182      1472   120         0.000000      1027.728392         0.000000 0 0 /
     radeon_cs:0   707      7005.506352        11   120         0.000000         1.386411         0.000000 0 0 /
        dhclient   708      4410.439050        29   120         0.000000         9.122386         0.000000 0 0 /

[...snip...]

          python  2837    188838.661437      5266   120         0.000000       699.150197         0.000000 0 0 /user.slice/
[...snip...]
```

*/proc/version*{: style="color: LightGreen"} - holds information about the kernel version
```
root@kali:~# cat /proc/version 
Linux version 4.13.0-kali1-amd64 (devel@kali.org) (gcc version 6.4.0 20171026 (Debian 6.4.0-9)) #1 SMP Debian 4.13.13-1kali1 (2017-11-17)
```

*/proc/bus/input/devices*{: style="color: LightGreen"} - could be used to enumerate input devices connected to the machine (keyboard, mouse, camera, touchpad...).
```
root@kali:~# cat /proc/bus/input/devices
I: Bus=0011 Vendor=0001 Product=0001 Version=ab41
N: Name="AT Translated Set 2 keyboard"
P: Phys=isa0060/serio0/input0
S: Sysfs=/devices/platform/i8042/serio0/input/input0
U: Uniq=
H: Handlers=sysrq kbd leds event0 
B: PROP=0
B: EV=120013
B: KEY=402000000 3803078f800d001 feffffdfffefffff fffffffffffffffe
B: MSC=10
B: LED=7

I: Bus=0003 Vendor=0458 Product=003a Version=0111
N: Name="Genius Optical Mouse"
[...snip...]

I: Bus=0011 Vendor=0002 Product=0007 Version=01b1
N: Name="SynPS/2 Synaptics TouchPad"
[...snip...]
```

*/proc/bus/pci/devices*{: style="color: LightGreen"} - enumerate PCI connected devices. Go to the right end.
```
0100    10026742        1d              b000000c                       0                c2000004                       0                    4001                       0                   c0002                10000000                       0                   20000                       0                     100                       0                   20000        radeon
0101    1002aa90        1e              c2020004                       0                       0                       0                       0                       0                       0                    4000                       0                       0                       0                       0                       0                       0        snd_hda_intel
0800    10ec8723        11                  3001                       0                c3000004                       0                       0                       0                       0                     100                       0                    4000                       0                       0                       0                       0        rtl8723ae
0900    10ec8136        18                  2001                       0                c000400c                       0                c000000c                       0                       0                     100                       0                    1000                       0                    4000                       0                       0        r8169
```

*/proc/uptime*{: style="color: LightGreen"} - the uptime of the machine.
```
root@kali:~# cat /proc/uptime 
11069.37 41314.72
```

*/proc/loadavg*{: style="color: LightGreen"} - the average load of the machine. Similar to what top shows.
```
root@kali:~# cat /proc/loadavg 
0.23 0.23 0.32 1/616 3225
```

*/proc/meminfo*{: style="color: LightGreen"} - holds information about RAM.

*/proc/cpuinfo*{: style="color: LightGreen"} - contains information about the CPU.

*/proc/sys*{: style="color: LightGreen"} - a directory which holds system configuration variables. For example if
*/proc/sys/net/ipv4/ip_forward*{: style="color: LightGreen"} is set to 1, that means the system can forward ipv4 packets (act as a router). The variables are too many to be listed in this post. You could explore on your own.

# <a name="config_files"></a> Default paths of configuration files
For completeness I'll list the default paths to some configuration files and other files valuable to an attacker.

*/root/.bashrc*{: style="color: LightGreen"} - executed every time an interactive shell (terminal) is opened.  
*/root/.profile*{: style="color: LightGreen"} - executed every time a user logs in.  
*/root/.bash_profile*{: style="color: LightGreen"} - executed every time the user logs in.  
*/root/.bash_history*{: style="color: LightGreen"} - history of the executed bash commands in terminal.  
*/root/.ssh/id_rsa*{: style="color: LightGreen"} - private rsa key of the root user.  
*/root/.ssh/authorized_keys*{: style="color: LightGreen"} - public keys of machines allowed to login via ssh as the root user.  
*/root/.ssh/known_hosts*{: style="color: LightGreen"} - hosts to which the root user connected via ssh.  

*/home/[username]/.bashrc*{: style="color: LightGreen"} - executed every time an interactive shell (terminal) is opened.  
*/home/[username]/.profile*{: style="color: LightGreen"} - executed every time a user logs in.  
*/home/[username]/.bash_profile*{: style="color: LightGreen"} - executed every time the user logs in.  
*/home/[username]/.bash_history*{: style="color: LightGreen"} - history of the executed bash commands in terminal.  
*/home/[username]/.ssh/id_rsa*{: style="color: LightGreen"} - private rsa key of the user.  
*/home/[username]/.ssh/authorized_keys*{: style="color: LightGreen"} - public keys of machines allowed to login via ssh as the user.  
*/home/[username]/.ssh/known_hosts*{: style="color: LightGreen"} - hosts to which the user connected via ssh.  

*/etc/ssh/sshd_config*{: style="color: LightGreen"} - ssh server configuration  
*/etc/ssh/ssh_host_rsa_key*{: style="color: LightGreen"} - private rsa key of the ssh server  
*/etc/ssh/ssh_host_rsa_key.pub*{: style="color: LightGreen"} - public rsa key of the ssh server  

*/etc/fstab*{: style="color: LightGreen"} - filesystems which the system mounts  
*/etc/passwd*{: style="color: LightGreen"} - could be used to enumerate users and services  
*/etc/shadow*{: style="color: LightGreen"} - contains the hashed passwords of the users  
*/etc/group*{: style="color: LightGreen"} - holds the existings groups and group memberships on the system  
*/etc/hosts*{: style="color: LightGreen"} - static DNS table lookup for hostnames  
*/etc/hostname*{: style="color: LightGreen"} - the hostname of the machine  
*/etc/issue*{: style="color: LightGreen"} - linux distribution  
*/etc/lsb-release*{: style="color: LightGreen"} - linux distribution and version information  
*/etc/resolv.conf*{: style="color: LightGreen"} - configured DNS nameservers  
*/etc/network/interfaces*{: style="color: LightGreen"} - static network interfaces configuration  
*/etc/crontab*{: style="color: LightGreen"} - the system crontab  
*/var/spool/cron/crontabs/[username]*{: style="color: LightGreen"} - the user crontab

*/var/log/apt/history.log*{: style="color: LightGreen"} - log of installed/removed apt packages. Could be used to enumerate installed programs.  

*/etc/apache2/apache2.conf*{: style="color: LightGreen"} - apache2 configuration  
*/etc/apache2/ports.conf*{: style="color: LightGreen"} - configuration of listening ports used by apache2  
*/etc/apache2/sites-enabled/000-default.conf*{: style="color: LightGreen"} - virtual host configuration  
*/etc/apache2/sites-available/000-default.conf*{: style="color: LightGreen"} - virtual host configuration  
*/usr/local/apache2/*{: style="color: LightGreen"} - if apache is installed from source, the default configuration files are found under this directory.   

*/var/www/html/*{: style="color: LightGreen"} - usually the default directory for the webpage source code and files. Should look for index.php or other well known files.  

*/etc/squid/squid.conf*{: style="color: LightGreen"} - squid proxy configuration file  

*/etc/nginx/nginx.conf*{: style="color: LightGreen"} - nginx configuration  
*/etc/nginx/sites-available/default*{: style="color: LightGreen"} - virtual host configuration  
*/etc/nginx/sites-enabled/default*{: style="color: LightGreen"} - virtual host configuration  

*/etc/php/[version]/cli/php.ini*{: style="color: LightGreen"} - php configuration file  
