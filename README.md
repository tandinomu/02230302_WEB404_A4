# WEB404 Practical Assignment 4: Command Injection

**Student ID:** 02230302
**Module:** WEB404, Secure Coding Practices
**Task:** Build a command-line tool in a web app, attack it with command injection, then fix it.

---

## 1. What is Command Injection?

Command injection happens when a web app puts user input into a system command
and runs it through a shell. The shell treats characters like `;`, `&&`, `||`,
`|` and `$(...)` as instructions, so an attacker can add their own commands.

This is listed in **OWASP Top 10 2021, A03 Injection** and as **CWE-78**.
It is dangerous because the attacker can read files, change data, or take over
the server.

---

## 2. Lab Setup

- One Docker container running PHP 8.3 and Apache.
- The tool does a host lookup with `getent hosts <host>`.
- The port is bound to `127.0.0.1:8088` only, so the lab is not reachable from
  the network. All tests use `127.0.0.1` / `localhost`.

```bash
docker compose up -d     # start the lab, then open http://127.0.0.1:8088/
docker compose down      # stop the lab
```

Files:
```
docker-compose.yml   # container setup
src/index.php        # landing page
src/vulnerable.php   # insecure version
src/secure.php       # fixed version
screenshots/         # evidence
```

### Step 1: Open the lab

![Landing page](screenshots/00_landing.png)

The landing page at `http://127.0.0.1:8088/`. It links to the vulnerable and
the secure version of the lookup tool.

---

## 3. The Vulnerable Version

The user input is joined into a string and run by the shell:

```php
$host = $_GET['host'];
$cmd = "getent hosts " . $host;
$output = shell_exec($cmd . " 2>&1");
```

`shell_exec()` sends the whole string to `/bin/sh`, so anything in `$host` can
run as a command.

### Step 2: Normal use of the vulnerable page

![Vulnerable page, normal lookup](screenshots/01_vulnerable_normal.png)

Input `127.0.0.1` runs `getent hosts 127.0.0.1` and returns
`127.0.0.1  localhost`. The tool works as intended.

### Attacks

| # | Input                                      | Result                          | Why it works                          |
|---|--------------------------------------------|---------------------------------|---------------------------------------|
| 1 | `127.0.0.1; id`                            | `uid=33(www-data) ...`          | `;` runs the next command             |
| 2 | `127.0.0.1 && whoami`                      | `www-data`                      | `&&` runs if the first one succeeds   |
| 3 | `doesnotexist \|\| id`                     | `uid=33(www-data) ...`          | `\|\|` runs if the first one fails    |
| 4 | `127.0.0.1 \| id`                          | `uid=33(www-data) ...`          | `\|` pipes into a second command      |
| 5 | `127.0.0.1; echo "ran as: $(whoami)"`      | `ran as: www-data`              | `$(...)` runs the inner command       |
| 6 | `127.0.0.1; cat /etc/passwd`               | Whole `/etc/passwd` file shown  | `;` chains a file read                |

### Step 3: Attack with a command separator

![Separator attack shows www-data](screenshots/02_attack_separator_id.png)

Input `127.0.0.1; id`. The `;` makes the shell run `id` after the lookup. The
output shows `uid=33(www-data)`, proving an extra command ran on the server.

### Step 4: Read a sensitive file

![/etc/passwd dumped](screenshots/03_attack_cat_passwd.png)

Input `127.0.0.1; cat /etc/passwd`. The page prints the whole `/etc/passwd`
file, which shows the attacker can read files from the server.

### Step 5: Attack with command substitution

![Command substitution](screenshots/04_attack_substitution.png)

Input `127.0.0.1; echo "substitution ran as: $(whoami)"`. The shell runs
`whoami` inside `$(...)` first and prints `substitution ran as: www-data`.

These steps prove that anyone can run any command on the server as the
`www-data` user.

---

## 4. The Secure Version

Two fixes are used together.

**Fix 1: No shell.** The command is passed as an array to `proc_open()`, so PHP
runs `getent` directly. The input is treated as one plain argument, and
characters like `;` mean nothing.

```php
$proc = proc_open(['getent', 'hosts', $host], $descriptors, $pipes);
```

**Fix 2: Whitelist validation.** Only a valid IPv4 address or hostname
(letters, digits, dots, hyphens) is accepted. Anything else is rejected and
nothing runs.

```php
function is_valid_host(string $host): bool {
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return true;
    }
    $pattern = '/^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
             . '(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/';
    return (bool) preg_match($pattern, $host);
}
```

**Least privilege:** the process runs as `www-data`, not root, which limits the
damage if something else goes wrong.

### Step 6: Normal use of the secure page

![Secure page, normal lookup](screenshots/05_secure_normal.png)

Input `127.0.0.1` still returns `127.0.0.1  localhost`. The fix does not
break normal use.

### Step 7: Separator attack is blocked

![Secure rejects ; id](screenshots/06_secure_rejects_separator.png)

Input `127.0.0.1; id` fails validation because `;` and the space are not
allowed. The page shows "Nothing was run." and no `id` output appears.

### Step 8: File read attack is blocked

![Secure rejects cat /etc/passwd](screenshots/07_secure_rejects_catpasswd.png)

Input `127.0.0.1; cat /etc/passwd` is rejected. Compare with Step 4: the file
is no longer shown.

### Step 9: Command substitution is blocked

![Secure rejects $(whoami)](screenshots/08_secure_rejects_substitution.png)

The `$(whoami)` input is rejected because `$`, `(` and `)` are not valid in a
hostname. Nothing runs.

---

## 5. Comparison

| Aspect            | Vulnerable                           | Secure                                   |
|-------------------|--------------------------------------|------------------------------------------|
| How it runs       | `shell_exec("getent hosts " . $host)` | `proc_open(['getent','hosts',$host])`   |
| Uses a shell?     | Yes                                  | No                                       |
| Input checked?    | No                                   | Yes, whitelist                           |
| `127.0.0.1; id`   | Runs `id`                            | Rejected                                 |

**Why a whitelist and not a blacklist?** A blacklist tries to block every bad
character, and it is easy to miss one. A whitelist only allows what is valid
and blocks everything else by default, so it is much safer.

---

## 6. Conclusion

The vulnerable page let a normal form field run `id`, `whoami` and
`cat /etc/passwd` on the server. The secure page fixed this by running the
program without a shell and only accepting valid hostnames or IPs. The main
lesson: **never build shell commands from user input.**

---

## References

- OWASP Top 10:2021, A03 Injection: https://owasp.org/Top10/A03_2021-Injection/
- CWE-78, OS Command Injection: https://cwe.mitre.org/data/definitions/78.html
- OWASP OS Command Injection Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
