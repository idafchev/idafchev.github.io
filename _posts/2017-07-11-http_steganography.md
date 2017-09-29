---
layout: post
date:   2017-07-10 15:12:01 -0600
categories: projects
description: "A PoC for hiding data in HTTP headers."
title:  "HTTP Steganography PoC"
author: "Iliya Dafchev"
---

I wrote a proof of concept for hiding and transfering data in the HTTP headers. I don't know if it's a unique idea (probably not), but I think it's an interesting one (although not very efficient) and I wanted to implement it.

You can find the source code [here](https://github.com/idafchev/stego_http).

For those who are not familiar, steganography is (as described in wikipedia) "the practice of concealing a file, message, image, or video within another file, message, image, or video.". So it's not only for hiding data in images.

The way my PoC works is the following:  
- The secret message is a text which is converted to binary format  
- The 1s are encoded as double space and 0s as single space  
- The spaces in the HTTP headers of the request are replaced with double space (1) or single space(0) (no change), depending on the current bit of the binary message  
- If the message is too long, multiple HTTP requests are sent  

Actually the first space in the header (the one after the colon) isn't used for hiding data, because it's visually easy to notice when there are two spaces. That's why I add a space (0) or double space(1) to all headers right before '\r\n' to retain the capacity. It's also harder to notice visually, because those are all whitespace symbols.

So instead of writing 1 as  
header:\_\_value\r\n  
I do  
header:\_value\_\_\r\n  

There aren't many spaces in the HTTP requests and headers, so the capacity (number of bits I could hide in a request) and throughput are really low. For my tests I used every header I could think of to maximize the capacity of the request (also, the longer the 'user-agent' header is, the better). Even so, the message "This is a very secret message!", needed 7 requests to be sent! It's obvious you couldn't use this to transfer even small files. Not only it's going to be sloooow, but the sysadmins will definately notice the large HTTP traffic coming from the machine. 

I think this technique is good only for malware C&C communication.

To increase capacity with a few bits, another layer of encoding could be used, for example after encoding with spaces, more data could be encoded using the number of upper/lower case letters or something similar.

Here is an example of two requests. The first one is without hidden data in it and the second one has hidden data in it.
```
GET /test/test.php?id=1 HTTP/1.1
accept-encoding: gzip, deflate, sdch
x-requested-with: XMLHttpRequest
accept: text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, */*;q=0.8
cache-control: must-revalidate, public, max-age=0
accept-language: bg-BG, bg;q=0.8, en;q=0.6, de;q=0.7
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36
referer: http://www.mysite.com/
dnt: 1
upgrade-insecure-requests: 1
host: 127.0.0.1
connection: keep-alive
accept-charset: utf-8, iso-8859-1;q=0.5, *;q=0.1


```

```
GET /test/test.php?id=1 HTTP/1.1
accept-encoding: gzip, deflate,  sdch 
x-requested-with: XMLHttpRequest  
accept: text/html, application/xhtml+xml,  application/xml;q=0.9, image/webp, */*;q=0.8 
cache-control: must-revalidate,  public,  max-age=0 
accept-language: bg-BG,  bg;q=0.8, en;q=0.6, de;q=0.7 
user-agent: Mozilla/5.0 (Windows  NT  10.0; Win64;  x64) AppleWebKit/537.36 (KHTML,  like Gecko)  Chrome/58.0.3029.110  Safari/537.36  
referer: http://www.mysite.com/ 
dnt: 1 
upgrade-insecure-requests: 1  
host: 127.0.0.1  
connection: keep-alive 
accept-charset: utf-8, iso-8859-1;q=0.5,  *;q=0.1 


```
The idea was that the traffic should look as real HTTP traffic as it can. The current PoC only sends predefined GET requests.

My PoC could be improved alot and make the traffic look as legitimate HTTP traffic as possible. For example the traffic could be predefined such that it simulates normal user activity. The server returns a real page, then other requests are sent to download the files and pictures from that page, after that other resources are requested from the site as if a real user is browsing it. All those requests can carry hidden data, and server responses could also hide data, not only in the headers but in the body (webpage source) too.

This technique could be made ineffective with http traffic normalization and anomaly detection.

Below are some screenshots from the PoC and it's traffic.

The id parameter is used to indicate the last request, so the server knows when to start decoding the message.
![stego_http01](/images/stego_http/stego_http01.png)

Wireshark capture.
![stego_http02](/images/stego_http/stego_http02.png)

Request with a hidden message.
![stego_http03](/images/stego_http/stego_http03.png)

Another request, but here you can see the spaces at the end of the headers, before '\r\n'
![stego_http04](/images/stego_http/stego_http04.png)
