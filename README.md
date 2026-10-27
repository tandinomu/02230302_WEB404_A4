# WEB404 Secure Coding Practices: Practical Assignment 4
## Building a Command-Line Web Tool and Defending Against OS Command Injection

**Student ID:** 02230302
**Module:** WEB404, Secure Coding Practices
**Task:** Create a command-line interface in a web application and implement
safeguards against command injection.

---

## Overview: what this assignment does and how

This assignment builds a small command-line web tool (a DNS/host lookup) and
then defends it against **OS command injection**.

The approach has three stages:

1. **Build a vulnerable version**: a page that runs a system command built by
   concatenating raw user input and passing it to a shell (`shell_exec`).
2. **Attack it**: use shell metacharacters (`;`, `&&`, `||`, `|`, `$(...)`) in
   an ordinary form field to run extra commands on the server (`id`, `whoami`,
   `cat /etc/passwd`).
3. **Secure it**: rebuild the tool with two layered defences: run the binary
   directly with an argument array (no shell at all) and validate input against a
   strict whitelist, then show every attack failing.

The core idea: **never build a shell command string from user input.**

---

## 1. Introduction

### What is OS command injection?
OS (operating system) command injection is a vulnerability where a web
application builds a **system command** using untrusted user input and then
runs that command through a **shell** (for example `/bin/sh`). Because the
shell treats certain characters as instructions (`;`, `&&`, `|`, `||`,
`$(...)`, `` `...` ``), an attacker can type those characters into an ordinary
form field and smuggle in **extra commands** that the server will run.

### Why is it dangerous?
The injected commands run with the privileges of the web-server process. An
attacker can:
- read sensitive files (e.g. `/etc/passwd`, source code, configuration,
  credentials),
- modify or delete data,
- install malware or open a reverse shell,
- pivot deeper into the network.

Command injection often leads to **full server compromise**, which is why it is
treated as a critical-severity issue.

### OWASP reference
This vulnerability belongs to **OWASP Top 10 2021, A03:2021 Injection**
(<https://owasp.org/Top10/A03_2021-Injection/>). Injection covers any flaw
where untrusted data is sent to an interpreter (SQL, OS shell, LDAP, etc.) as
part of a command or query. The matching weakness is **CWE-78: Improper
Neutralization of Special Elements used in an OS Command**.

---

## 2. Lab Setup and Ethical Considerations

### Architecture
A single Docker container running PHP 8.3 with the Apache web server. Apache
serves the PHP pages; PHP performs the DNS lookup. The chosen lookup command is
`getent hosts <host>`, which ships with the base image (so nothing extra had to
be installed) and behaves like a DNS/hosts lookup.

```
your browser / curl  ->  127.0.0.1:8088  ->  Docker container (Apache + PHP 8.3)
                                                     |
                                              getent hosts <host>
```

### Ethical considerations
- **Everything is local.** The port is published as `127.0.0.1:8088:80`, i.e.
  bound to the **loopback address only**. The lab cannot be reached from the
  local network or the internet, so the deliberately vulnerable page can never
  be attacked by (or attack) anyone else.
- **No external targets.** Every test uses `127.0.0.1` / `localhost`. No real
  or third-party host is ever scanned or attacked.
- The vulnerable file is clearly labelled as insecure and is for learning only.

### How to run
```bash
docker compose up -d            # start the lab
# open http://127.0.0.1:8088/   in a browser
docker compose down             # stop and remove the container
```

Files:
```
.
├── docker-compose.yml   # the container definition (loopback-only port)
├── src/
│   ├── index.php        # landing page linking to both versions
│   ├── vulnerable.php   # INSECURE version (teaching example)
│   └── secure.php       # SECURE version (the fix)
├── screenshots/         # evidence screenshots
└── README.md            # this report
```

[SCREENSHOT: landing page at http://127.0.0.1:8088/, screenshots/00_landing.png]

---

## 3. The Vulnerable Version

### The vulnerable code (`src/vulnerable.php`)
The flaw is that raw user input is concatenated into a command **string** and
run through a shell with `shell_exec()`:

```php
// Take the user input EXACTLY as typed, no checks, no escaping.
$host = $_GET['host'];

// Build the command by concatenating the raw input into a string.
// THIS is the vulnerability: $host can contain shell metacharacters.
$cmd = "getent hosts " . $host;

// shell_exec() runs the string through /bin/sh, which interprets
// any shell syntax inside $host.
$output = shell_exec($cmd . " 2>&1");
```

**Why this is vulnerable:** `shell_exec()` hands the whole string to `/bin/sh`.
The shell parses the string for *its own* special characters **before** running
anything, so anything the user types in `$host` can be interpreted as shell
code rather than as a hostname.

> Note: the page wraps its *output* in `htmlspecialchars()`, but that only makes
> the result safe to **display** in HTML (it defends against XSS). The command
> injection already happened inside `shell_exec()` **before** any HTML encoding,
> so `htmlspecialchars()` does nothing to prevent it.

### Normal, intended use
Input `127.0.0.1` runs `getent hosts 127.0.0.1` and returns:
```
127.0.0.1       localhost
```
[SCREENSHOT: vulnerable page, normal lookup, screenshots/01_vulnerable_normal.png]

### The attacks

For each attack: the **input** typed into the host field, the **output**
observed, and **why** the shell obeyed.

#### Attack 1: Command separator `;`
- **Input:** `127.0.0.1; id`
- **Command run:** `getent hosts 127.0.0.1; id`
- **Output:**
  ```
  127.0.0.1       localhost
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ```
- **Why:** `;` means "then run the next command", unconditionally. The shell
  sees two commands and runs both.

[SCREENSHOT: separator attack showing uid=33(www-data), screenshots/02_attack_separator_id.png]

#### Attack 2: Logical AND `&&`
- **Input:** `127.0.0.1 && whoami`
- **Output:** `127.0.0.1  localhost` then `www-data`
- **Why:** `&&` runs the second command only if the first **succeeds** (exit
  code 0). The lookup succeeded, so `whoami` ran.

#### Attack 3: Logical OR `||`
- **Input:** `doesnotexist || id`
- **Output:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
- **Why:** `||` runs the second command only if the first **fails**. The lookup
  of a bogus host failed, so `id` ran.

#### Attack 4: Pipe `|`
- **Input:** `127.0.0.1 | id`
- **Output:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
- **Why:** `|` sends the first command's output into the second command. `id`
  ignores that input and runs anyway, printing the server's identity.

#### Attack 5: Command substitution `$(...)`
- **Input:** `127.0.0.1; echo "substitution ran as: $(whoami)"`
- **Output:** `substitution ran as: www-data`
- **Why:** `$(...)` tells the shell to run the inner command **first** and paste
  its output into the command line. This proves arbitrary inner commands
  execute. (Backticks `` `...` `` are the older form and behave the same, e.g.
  input `` 127.0.0.1; echo result=`id -un` `` returns `result=www-data`.)

[SCREENSHOT: command substitution proof, screenshots/04_attack_substitution.png]

#### Attack 6: Reading a sensitive file
- **Input:** `127.0.0.1; cat /etc/passwd`
- **Output:** the entire `/etc/passwd` file, including:
  ```
  root:x:0:0:root:/root:/bin/bash
  ...
  www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
  ...
  ```
- **Why:** `;` chains a second command that reads a sensitive file the web user
  is allowed to read. This is real information disclosure.

[SCREENSHOT: /etc/passwd dumped through the form, screenshots/03_attack_cat_passwd.png]

### What the attacks prove
- **Arbitrary command execution** on the server through a normal form field.
- **The process runs as `www-data`** (uid 33), the Apache worker user, shown by
  `id` / `whoami` in every attack. Not root here, but `www-data` can still read
  source, config and `/etc/passwd`, and could attempt privilege escalation.

---

## 4. The Secure Version

The fix uses **two independent safeguards**, strongest first.

### Safeguard 1 (strongest): Avoid the shell entirely
Instead of building a string for `/bin/sh`, pass the program and its arguments
as a **list** to `proc_open()`. PHP then launches the binary **directly**, with
no shell in between, so shell metacharacters are never interpreted, the whole
user input is delivered to `getent` as **one literal hostname argument**.

```php
// An ARRAY, not a string. proc_open runs getent directly, with NO /bin/sh.
$proc = proc_open(['getent', 'hosts', $host], $descriptors, $pipes);
```

**Proof it works on its own:** feeding the attack string `127.0.0.1; id`
straight into this array form (bypassing validation) produces **no output and
no `id` result**, `getent` just fails to resolve the literal string
`127.0.0.1; id` as a hostname. There is no shell, so there is nothing to inject
into.

### Safeguard 2: Strict whitelist validation
Before running anything, the input must match **exactly** a valid IPv4 address
**or** a valid hostname. Anything else is rejected and nothing runs.

```php
function is_valid_host(string $host): bool {
    // Accept a well-formed IPv4 address, e.g. 127.0.0.1
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return true;
    }
    // Accept a hostname: dot-separated labels of letters/digits/hyphens only.
    $pattern = '/^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
             . '(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/';
    return (bool) preg_match($pattern, $host);
}
```

A valid hostname/IP contains only letters, digits, dots and hyphens, **none**
of the shell metacharacters. So any injection attempt fails validation
immediately.

### Least privilege (supporting control)
The lookup process runs as the unprivileged **`www-data`** user, not root, so
even a successful attack would be limited. In production you would go further:
run the container as a dedicated non-root user, drop Linux capabilities, mount
the filesystem read-only, and give the process only the access it truly needs.
Least privilege does not *prevent* injection; it **reduces the blast radius**
if another control fails.

### Legitimate use still works
- Input `127.0.0.1` → `127.0.0.1  localhost`
- Input `localhost` → `::1  localhost ip6-localhost ip6-loopback`

[SCREENSHOT: secure page, normal lookup works, screenshots/05_secure_normal.png]

### The same attacks, now failing

Every attack from Section 3, re-run against `secure.php`, is now **rejected**
before any command runs:

| Input (host field)              | Result on secure page                 |
|---------------------------------|---------------------------------------|
| `127.0.0.1; id`                 | Rejected: "Nothing was run."         |
| `127.0.0.1 && whoami`           | Rejected: "Nothing was run."         |
| `doesnotexist \|\| id`          | Rejected: "Nothing was run."         |
| `127.0.0.1 \| id`               | Rejected: "Nothing was run."         |
| `$(id)`                         | Rejected: "Nothing was run."         |
| `` `whoami` ``                  | Rejected: "Nothing was run."         |
| `127.0.0.1; cat /etc/passwd`    | Rejected: "Nothing was run."         |

[SCREENSHOT: secure page rejects the separator attack, screenshots/06_secure_rejects_separator.png]

[SCREENSHOT: secure page rejects cat /etc/passwd (compare to screenshot 03), screenshots/07_secure_rejects_catpasswd.png]

---

## 5. Vulnerable vs Secure: Comparison

| Aspect                | Vulnerable (`vulnerable.php`)          | Secure (`secure.php`)                         |
|-----------------------|----------------------------------------|-----------------------------------------------|
| How the command runs  | `shell_exec("getent hosts " . $host)`  | `proc_open(['getent','hosts',$host], ...)`    |
| Shell involved?       | Yes: `/bin/sh` parses the string      | No: the binary is run directly               |
| Input handling        | Raw, concatenated, trusted             | Validated against a strict whitelist          |
| `;`, `&&`, `$()` etc. | Interpreted as shell instructions      | Literal characters / rejected before running  |
| `127.0.0.1; id`       | Runs `id` as www-data                  | Rejected, nothing runs                        |
| Result                | Full command execution                 | Attack neutralised                            |

### Why whitelisting beats blacklisting
A **blacklist** tries to list every "bad" thing to block (e.g. strip `;`, `&`,
`|`). This is weak because:
- It is **easy to miss** a dangerous character or combination, you must think
  of *every* one (`;`, `&&`, `||`, `|`, `` ` ``, `$()`, `\n`, `>`, `<`, `&`,
  spaces, `$IFS`, …). Miss one and the defence fails.
- Attackers find **encodings and bypasses** (newlines, Unicode look-alikes,
  nested substitution) faster than defenders can patch the list.
- It fails **open**: anything not explicitly banned is allowed through.

A **whitelist** defines what is **valid** and rejects everything else. For a
hostname that is simply "letters, digits, dots and hyphens". It fails **closed**:
unexpected input is denied by default, so you don't have to predict every
attack. That is why whitelisting is the recommended approach.

> Best of all, in this lab the primary fix doesn't rely on filtering characters
> at all: by removing the shell (Safeguard 1), those characters have **no
> special meaning** in the first place. Validation is the second layer.

---

## 6. Conclusion

OS command injection happens when untrusted input reaches a shell as part of a
command. The vulnerable page showed how a single form field could run `id`,
`whoami` and `cat /etc/passwd` on the server as the `www-data` user. The secure
page closed the hole with defence in depth: **(1)** run the binary directly with
an argument array so no shell ever interprets the input, and **(2)** accept only
input matching a strict IP/hostname whitelist, backed by the principle of least
privilege. The key lessons: never build shell command strings from user input,
prefer argument-list APIs over the shell, and validate with a whitelist rather
than a blacklist.

---

## 7. Screenshot Checklist

- [ ] `screenshots/00_landing.png`, landing page (optional)
- [ ] `screenshots/01_vulnerable_normal.png`, vulnerable page, normal lookup
- [ ] `screenshots/02_attack_separator_id.png`, `127.0.0.1; id` shows www-data
- [ ] `screenshots/03_attack_cat_passwd.png`, `/etc/passwd` dumped via the form
- [ ] `screenshots/04_attack_substitution.png`, `$(whoami)` substitution (optional)
- [ ] `screenshots/05_secure_normal.png`, secure page, normal lookup works
- [ ] `screenshots/06_secure_rejects_separator.png`, secure rejects `; id`
- [ ] `screenshots/07_secure_rejects_catpasswd.png`, secure rejects `cat /etc/passwd`
- [ ] `screenshots/08_secure_rejects_substitution.png`, secure rejects `$(whoami)` (optional)

---

## References

- OWASP Top 10:2021, A03 Injection, https://owasp.org/Top10/A03_2021-Injection/
- CWE-78: Improper Neutralization of Special Elements used in an OS Command, https://cwe.mitre.org/data/definitions/78.html
- OWASP OS Command Injection Defense Cheat Sheet, https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
