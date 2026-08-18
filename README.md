<img src=https://github.com/Industri4l-H3ll-Xpl0it3rs/recontr/blob/main/logo.png width=900>

# recontr

cr34t3d by [infrar3d](https://github.com/Infrar3dd)

`recontr` is a lightweight Linux process and container reconnaissance tool designed to inspect running processes, Linux namespaces, capabilities, cgroups, container isolation mechanisms, and exposed container runtime sockets.

The tool analyzes `/proc` without requiring external dependencies and helps identify processes that are likely running inside containers, as well as potentially interesting security-related configurations such as privileged capabilities, disabled seccomp, root execution, and writable container control sockets.

### Features

* Enumerates running Linux processes through `/proc`.
* Inspects Linux namespaces:

  * PID
  * Mount
  * Network
  * UTS
  * IPC
  * User
  * Cgroup
* Compares process namespaces against PID 1 to detect namespace isolation.
* Uses heuristic scoring to identify processes likely running inside containers.
* Detects common container environments through cgroup information:

  * Docker
  * Kubernetes
  * containerd
  * Podman
  * LXC
  * systemd-machine
* Decodes Linux process capabilities from `CapEff`.
* Highlights security-relevant capabilities such as:

  * `CAP_SYS_ADMIN`
  * `CAP_SYS_PTRACE`
  * `CAP_SYS_MODULE`
  * `CAP_SYS_RAWIO`
  * `CAP_NET_ADMIN`
  * `CAP_DAC_OVERRIDE`
  * `CAP_SETUID`
  * `CAP_SETGID`
  * `CAP_BPF`
* Detects processes running as `root`.
* Checks process security settings:

  * Seccomp
  * `NoNewPrivs`
* Reports potentially interesting findings such as:

  * `runs-as-root`
  * `CAP_SYS_ADMIN`
  * `CAP_SYS_PTRACE`
  * `CAP_SYS_MODULE`
  * `seccomp-disabled`
  * `no-new-privs-disabled`
* Checks for exposed container runtime sockets:

  * `/var/run/docker.sock`
  * `/run/docker.sock`
  * `/run/containerd/containerd.sock`
  * `/run/podman/podman.sock`
  * `/var/run/crio/crio.sock`
* Detects whether discovered runtime sockets are writable.
* Supports filtering output to processes likely running in containers.
* Supports exporting complete reconnaissance results to JSON.
* Uses only the Python standard library.

### Installation/Requirements

#### Requirements

* Linux operating system with `/proc` mounted.
* Python 3.
* Permission to inspect the target processes under `/proc`.

Some process information may not be accessible to an unprivileged user because of Linux permission restrictions, namespace isolation, or `/proc` security settings.

Running the tool with elevated privileges may provide more complete results:

```bash
sudo python3 recontr.py
```

#### Installation

Clone the repository:

```bash
git clone https://github.com/Industri4l-H3ll-Xpl0it3rs/recontr.git
cd recontr
```

Make the script executable:

```bash
chmod +x recontr.py
```

Run it:

```bash
./recontr.py
```

Alternatively:

```bash
python3 recontr.py
```

### Usage:

```bash
python3 recontr.py --help    

▀▀▀▀▀▀▓▓▄ ▀▀▀▀▀▀▓▓▀ ▀▀▀▀▀▀▓▓▀ ▀▀▀▀▀▀▓▓▄ ▀▀▀▀▀▀▓▓▄ ▀▀▓▓▓▀▀ ▀▀▀▀▀▀▓▓▄
▒▒▒▀▀▀▒▒▄ ▒▒▒▀▀ ▀   ▒▒▒ █ ▀   ▒▒▒ █ ▒▒▓ ▒▒▒ █ ▒▒▒ █ ▒▒▒ █ ▒▒▒▀▀▀▒▒▄
░░░ █ ░░░ ░░░ ▀ ░░░ ░░░ ▀ ░░░ ░░░ ▀ ░░░ ░░░ █ ░░░ █ ░░░ █ ░░░ █ ░░░
▀▀▀   ▀▀▀  ▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀  ▀▀▀   ▀▀▀   ▀▀▀   ▀▀▀   ▀▀▀
                                                        by infrar3d

usage: recontr.py [-h] [--containers-only] [--json JSON_FILE]

Linux process/container namespace reconnaissance tool

options:
  -h, --help         show this help message and exit
  --containers-only  Only display processes likely running in containers
  --json JSON_FILE   Export complete results to JSON


```

### Example:

```bash
admin@ubuntu:~$ python3 recontr.py 

▀▀▀▀▀▀▓▓▄ ▀▀▀▀▀▀▓▓▀ ▀▀▀▀▀▀▓▓▀ ▀▀▀▀▀▀▓▓▄ ▀▀▀▀▀▀▓▓▄ ▀▀▓▓▓▀▀ ▀▀▀▀▀▀▓▓▄
▒▒▒▀▀▀▒▒▄ ▒▒▒▀▀ ▀   ▒▒▒ █ ▀   ▒▒▒ █ ▒▒▓ ▒▒▒ █ ▒▒▒ █ ▒▒▒ █ ▒▒▒▀▀▀▒▒▄
░░░ █ ░░░ ░░░ ▀ ░░░ ░░░ ▀ ░░░ ░░░ ▀ ░░░ ░░░ █ ░░░ █ ░░░ █ ░░░ █ ░░░
▀▀▀   ▀▀▀  ▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀  ▀▀▀   ▀▀▀   ▀▀▀   ▀▀▀   ▀▀▀
                                                        by infrar3d                                                                       

PID     USER           PROCESS               CONTAINER   RUNTIME       NAMESPACES               FINDINGS                                                                                                                                    
------------------------------------------------------------------------------------------------------------------------                                                                                                                    
1       root           systemd               LOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled                                             
2       root           kthreadd              LOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled                                             
3       root           pool_workqueue_releaseLOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled                                             
4       root           kworker/R-rcu_gp      LOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled                                             
5       root           kworker/R-sync_wq     LOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled                                             
6       root           kworker/R-kvfree_rcu_reclaimLOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled                                       
7       root           kworker/R-slub_flushwqLOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled                                             
8       root           kworker/R-netns       LOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled                                             
9       root           kworker/0:0-mm_percpu_wqLOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled                                           
10      root           kworker/0:0H-kblockd  LOW         -             -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled
```

```bash
admin@ubuntu:~$ python3 recontr.py --containers-only

▀▀▀▀▀▀▓▓▄ ▀▀▀▀▀▀▓▓▀ ▀▀▀▀▀▀▓▓▀ ▀▀▀▀▀▀▓▓▄ ▀▀▀▀▀▀▓▓▄ ▀▀▓▓▓▀▀ ▀▀▀▀▀▀▓▓▄
▒▒▒▀▀▀▒▒▄ ▒▒▒▀▀ ▀   ▒▒▒ █ ▀   ▒▒▒ █ ▒▒▓ ▒▒▒ █ ▒▒▒ █ ▒▒▒ █ ▒▒▒▀▀▀▒▒▄
░░░ █ ░░░ ░░░ ▀ ░░░ ░░░ ▀ ░░░ ░░░ ▀ ░░░ ░░░ █ ░░░ █ ░░░ █ ░░░ █ ░░░
▀▀▀   ▀▀▀  ▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀  ▀▀▀   ▀▀▀   ▀▀▀   ▀▀▀   ▀▀▀
                                                        by infrar3d

PID     USER           PROCESS               CONTAINER   RUNTIME       NAMESPACES               FINDINGS
------------------------------------------------------------------------------------------------------------------------
1386    root           containerd            MEDIUM      containerd    -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled
1465    root           dockerd               MEDIUM      Docker        -                        runs-as-root,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_MODULE,seccomp-disabled,no-new-privs-disabled

Container control sockets
----------------------------------------------------------------------
/var/run/docker.sock                          socket
/run/docker.sock                              socket
/run/containerd/containerd.sock               socket

```

### ⚠️ Disclaimer ⚠️

This software and proof-of-concept code is provided **for educational and research purposes only**. 

*   The authors are **not responsible** for any misuse or damage caused by this program.
*   **Do not use** against any systems without explicit **prior permission**.
*   Use of this tools for attacking targets without consent is **illegal**.

You are responsible for obeying all applicable laws. **Use ethically and responsibly.**

