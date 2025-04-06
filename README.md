# Landlocked

> [!WARNING]
> This document is intended for educational and informational purposes only. The content within this repository is provided on an 'as is' basis, and the author  make no representations or warranties of any kind, express or implied, about the completeness, accuracy, reliability, suitability, or availability of the information contained within this repository. Any reliance you place on such information is therefore strictly at your own risk.
> <br><br>The author shall in no event be liable for any loss or damage, including without limitation, indirect or consequential loss or damage, or any loss or damage whatsoever arising from loss of data or profits arising out of, or in connection with, the use of this document.
> <br><br>Furthermore, the techniques described in this document are provided for educational and informational purposes only, and should not be used for any illegal or malicious activities. The author do not condone or support any illegal or unethical activities, and any use of the information contained within this research is at the user's own risk and discretion.
> <br><br>The user is solely responsible for any actions taken based on the information contained within this document, and should always seek professional advice and assistance when attempting to implement any of the techniques described herein.
> <br><br>By using this document, the user agrees to release the author from any and all liability and responsibility for any damages, losses, or harm that may result from the use of this document or any of the information contained within it.

## Introduction

Mickaël Salaün SSTIC 2024's talk [Landlock: From a security mechanism idea to a widely available implementation](https://www.sstic.org/2024/presentation/landlock-design/) made me wonder if Landlock could be abused by a threat actor in any way and how?

Landlocked is a project that combine Landlock with other features to perform both defensive and offensive actions on a Linux system.

This document does not disclose any vulnerability, it explores how threat actors could abuse native sandboxing features implemented by the Linux kernel to perform malicious actions and ways of detecting this type of abuse.

> [!NOTE]
> All experiments described in this document were performed on an up-to-date Ubuntu 24.04 LTS machine.

> [!TIP]
> For CTF lovers, this document can probably be used to create interesting challenges too.

## Landlock

[Landlock](https://landlock.io/) was introduced in Linux kernel 5.13 in 2021.

Here is the description found in the [man page](https://docs.kernel.org/userspace-api/landlock.html)

    Landlock is an access-control system that enables any processes to
    securely restrict themselves and their future children.  Because
    Landlock is a stackable Linux Security Module (LSM), it makes it
    possible to create safe security sandboxes as new security layers
    in addition to the existing system-wide access-controls.  This
    kind of sandbox is expected to help mitigate the security impact
    of bugs, and unexpected or malicious behaviors in applications.

As developer who cares about security ensuring that your program performs as designed and that any flaw in its design will not conduct to accessing resources out of a specified scope is a must. Landlock is a **defensive programming** mechanism that fulfils this use case perfectly. It is well designed and easy to use. Ergonomy is key for security adoption.


## Dynamic Loader and Shared Object Constructor

Enter dynamic loading and shared object constructor!

### Dynamic Loader

[ld.so](https://www.man7.org/linux/man-pages/man8/ld.so.8.html) is responsible for loading libraries for dynamically linked executables on a Linux system.

The following part of the man page is important because it highlights one limitation of the technique described in this research.

    Linux binaries require dynamic linking (linking at run time)
    unless the -static option was given to ld(1) during compilation.

The dynamic loader comes with another interesting mechanism called `preloading`

    LD_PRELOAD
        A list of additional, user-specified, ELF shared objects to
        be loaded before all others.  This feature can be used to
        selectively override functions in other shared objects.
        The items of the list can be separated by spaces or colons,
        and there is no support for escaping either separator.  The
        objects are searched for using the rules given under
        DESCRIPTION.  Objects are searched for and added to the
        link map in the left-to-right order specified in the list.
        In secure-execution mode, preload pathnames containing
        slashes are ignored.  Furthermore, shared objects are
        preloaded only from the standard search directories and
        only if they have set-user-ID mode bit enabled (which is
        not typical).
        Within the names specified in the LD_PRELOAD list, the
        dynamic linker understands the tokens $ORIGIN, $LIB, and
        $PLATFORM (or the versions using curly braces around the
        names) as described above in Dynamic string tokens.  (See
        also the discussion of quoting under the description of
        LD_LIBRARY_PATH.)
        There are various methods of specifying libraries to be
        preloaded, and these are handled in the following order:
        (1)  The LD_PRELOAD environment variable.
        (2)  The --preload command-line option when invoking the
             dynamic linker directly.
        (3)  The /etc/ld.so.preload file (described below).


### Shared Object Constructor

GNU C allows to add attributes to functions such as `__attribute__((constructor))` which is the one that will be used in this research.

Here is the description found in the [documentation](https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Common-Function-Attributes.html)

    The constructor attribute causes the function to be called automatically
    before execution enters main (). Similarly, the destructor attribute causes
    the function to be called automatically after main () completes or exit ()
    is called. Functions with these attributes are useful for initializing data
    that is used implicitly during the execution of the program.


## Landlock Shared Object

> [!NOTE]
> From now on:
> - LSO is an alias for **L**andlock **S**hared **O**bject
> - DLE is an alias for **D**ynamically **L**inked **E**xecutable
> - SLE is an alias for **S**tatically **L**inked **E**xecutable

Once combined, all these features allow us to do interesting things. Let's do a step by step walk in the land of LSOs.

First, we create a shared object with a constructor enforcing a Landlock policy restricting a network operation. This kind of policy can be applied since version 4 of the landlock ABI.

Let's consider [noconnect](noconnect/) as an example to illustrate this concept.

```c
/* noconnect/noconnect.c */
#include <linux/landlock.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "noconnect.h"
#include "landlocked.h"

void __noconnect_destructor(void)
{
    I("called");
    return;
}

void __noconnect_constructor(void)
{
    struct landlocked_ctx ctx;
    struct landlock_ruleset_attr attr = {0};
    I("called");
    I("version %d.%d", NOCONNECT_VERSION_MAJOR, NOCONNECT_VERSION_MINOR);
#ifdef NOCONNECT_RANDOM
    IF_SUCCESS(__landlocked_random(10))
    {
        I("random exemption");
        goto end;
    }
#endif
    IF_FAILURE(__landlocked_init(&ctx))
    {
        E("__landlocked_init failure!");
        goto end;
    }
    attr.handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP;
    IF_FAILURE(__landlocked_create_ruleset(&ctx, &attr))
    {
        E("__landlocked_create_ruleset failure!");
        goto end;
    }
    IF_FAILURE(__landlocked_enforce(&ctx))
    {
        E("__landlocked_enforce failure!");
        goto end;
    }
end:
    __landlocked_free(&ctx);
    return;
}
```

When compiled we obtain a shared object called `noconnect.so` that we can preload into any DLE on the system.

Assuming that a SSH server is listening locally on port 22. Here is a normal run for `nc` against SSH port on the loopback.

```bash
nc -z -v 127.0.0.1 22
```
```
Connection to 127.0.0.1 22 port [tcp/ssh] succeeded!
```

Now let's see what happens when `noconnect.so` is preloaded when running `nc`.

```bash
LD_PRELOAD=./noconnect.so nc -z -v 127.0.0.1 22
```
```
nc: connect to 127.0.0.1 port 22 (tcp) failed: Permission denied
```

Here, `LD_PRELOAD` environment variable allowed to preload our Landlock plugin for `nc` as specified in the command line. As any environment variable, it can be set through systemd service configuration files, wrappers or user shell profile files.

Finally let's see what happens when `busybox nc` is used with the `LD_PRELOAD` environment variable.

```bash
LD_PRELOAD=./noconnect.so busybox nc 127.0.0.1 22
```
```
SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.8
^C
```

This last test highlights an important limitation, **SLEs are immune to preloading** because they do not require the dynamic loader.

You can identify SLEs in your system using the following command

```bash
find / -type f -executable -print -exec ldd {} \; 2>&1 |
    grep -B1 'not a dynamic' |
    grep '^/'
```

What about a system-wide preloaded Landlock plugin? The _one LSO to rule all DLEs_ scenario can be implemented thanks to `/etc/ld.so.preload`. This configuration file instructs the dynamic loader to preload our LSO in every userland process, even root's processes. When using this technique, note that already running processes based on DLEs are not affected by system-wide preloading. Beware of this technique, depending on your LSO, doing this may have a significant impact on overall system performance.


## LSO Use Cases

LSO use cases are both defensive and offensive. Despite the SLE limitation, we can still perform a whole range of actions with this technique.


### Defensive Use Cases

#### Landlock As Advertised

Developers can use Landlock policies to mitigate post-exploitation actions when a vulnerability is discovered in their project. It can also protect from unexpected behavior related to bugs that are not vulnerabilities.


#### Landlock The Careless

If the developers of your favorite project do not care about security you can enforce a Landlock policy as long as their software rely on DLEs.

This can be applied to systemd services and other programs individually through the `LD_PRELOAD` environment variable and configuration files.


### Offensive Use Cases

Nothing new in this section, every use case can already be implemented without using Landlock. That said, it is always nice to have several ways to reach the same objective to maximize the chances of success. Landlock is also a valuable, legit, native and efficient feature available for some interesting post-exploitation use cases.


#### Deletion Resistant System Locker

In this scenario one wants to reach a state of reversible paralysis for a machine.

As a proof of concept, [lockdown](lockdown/) implements system-wide restrictions that disable a system and prevent removal of its components through simple efficient means.

It is reversible in the way that it can be removed without data loss

- edit boot command to drop into a shell and use a SLE to remove lockdown components
- booting on a live usb and remove lockdown components

These deletion techniques do not scale well though. It could be challenging to fix an important quantity of infected machines.


#### Degrade System Performance

In this scenario one wants to make a system unstable to degrade its performance.

As a proof of concept, [noconnect](noconnect/) compiled with `random` option will prevent approximately 10 out off 256 new processes to create outgoing TCP connections as long as they run. This will lead to the infected machine showing erratic behavior.


#### Behavior Modification

In this scenario one wants to slightly modify the behavior of a program.

An LSO can gather context on the process it is preloaded for using the following functions:

- [getuid(2)](https://www.man7.org/linux/man-pages/man2/getuid.2.html)
- [getpid(2)](https://www.man7.org/linux/man-pages/man2/getpid.2.html)
- [getppid(2)](https://www.man7.org/linux/man-pages/man2/getppid.2.html)
- [realpath(3)](https://www.man7.org/linux/man-pages/man3/realpath.3.html)

This means that a system-wide Landlock plugin can behave differently depending on the program it is preloaded for.

As a proof of concept, [nomod](nomod/) applies a landlock policy only when `/usr/bin/kmod` is used and denies read access to some files in `/sys/module/xor`.

```bash
lsmod > /tmp/lsmod.out && grep -P '^xor\s+\d+' /tmp/lsmod.out
```
```
xor                    20480  1 async_xor
```

The normal behavior of `lsmod` is to exit with code `0` and display a count of 4 modules.

```bash
LD_PRELOAD=./nomod/nomod.so lsmod > /tmp/lsmod.out && grep -P '^xor\s+\d+' /tmp/lsmod.out
```
```
xor                    20480  -13 async_xor
```

We notice that once preloaded, our LSO modifies successfully the output of `lsmod` without changing its exit code `0`.

> [!IMPORTANT]
> This is just an example of a DLE whose behavior can be modified using this technique and the impact depends heavily on the specifics of the situation yet it may well be severe.


## Detecting Landlock Use

### Strace

`strace` shows Landlock syscalls for the tracee:

```bash
LD_PRELOAD=./nomod/nomod.so \
    strace \
    --trace=landlock_create_ruleset,landlock_add_rule,landlock_restrict_self \
    lsmod
```
```
landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) = 4
landlock_create_ruleset({handled_access_fs=LANDLOCK_ACCESS_FS_READ_FILE, handled_access_net=0}, 16, 0) = 3
landlock_add_rule(3, LANDLOCK_RULE_PATH_BENEATH, {allowed_access=LANDLOCK_ACCESS_FS_READ_FILE, parent_fd=5}, 0) = 0
[...]
landlock_add_rule(3, LANDLOCK_RULE_PATH_BENEATH, {allowed_access=LANDLOCK_ACCESS_FS_READ_FILE, parent_fd=5}, 0) = 0
landlock_restrict_self(3, 0)            = 0
```


### Auditd

This `auditd` rule allows to log a reasonable amount of information indicating the use of Landlock and monitor changes made to `ld.so.preload`.

```
-a always,exit -S landlock_create_ruleset -S landlock_restrict_self -k r_landlock
-w /etc/ld.so.preload -p wa -k r_global_preload
```


### Capa

This `capa` rule allows to detect binaries performing Landlock related syscalls.

```yaml
rule:
  meta:
    name: Performs Landlock Syscalls
    namespace: syscall/landlock
    authors:
      - koromodako
    scopes:
      static: basic block
      dynamic: call
  features:
    - and:
      - api: syscall
      - mnemonic: mov
      - or:
        - number: 444
        - number: 445
        - number: 446
```
