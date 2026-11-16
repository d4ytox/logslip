# Security policy

This repository holds a local privilege-escalation proof-of-concept for the
logrotate rename-then-create directory-swap race (CWE-362), the technique
Wolfgang Hotwagner found and automated in logrotten. It is not a vulnerability
in logrotate itself: logrotate behaves as configured, and the exposure comes
from a setup where an unprivileged user owns a log directory that root-run
logrotate rotates with `create` and no `su`. The canonical real-world instance
is CVE-2019-10143 (FreeRADIUS). The code is published for security education and
for authorised testing against systems you own or have written permission to
test.

## Reporting

This is research material rather than a maintained product, so there is no
vulnerability-reporting process for this repository. If you find a bug in the
PoC, open an issue.

## Intended use

For authorised testing and research only. logslip drops a file that executes as
root on the target and, with a reverse-shell payload, hands back a root shell.
Do not point it at a system you do not own or have written permission to test.

The example payload is guarded to fire only for root and to remove itself; the
path of anything dropped is printed on a win so you can clean up.

## What is demonstrated

Local privilege escalation from an unprivileged user to root by winning the
microsecond window between logrotate's rename and create, swapping the log
directory for a symlink so root writes an attacker-controlled file into a
privileged directory. The mitigation is the `su` directive, a root-owned
non-writable log directory, or a MAC policy; any one of them closes it.
