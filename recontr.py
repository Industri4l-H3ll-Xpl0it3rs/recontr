#!/usr/bin/env python3

import argparse
import json
import os
import pwd
import stat
from pathlib import Path


PROC = Path("/proc")

NAMESPACES = [
    "pid",
    "mnt",
    "net",
    "uts",
    "ipc",
    "user",
    "cgroup",
]

CAPABILITIES = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

INTERESTING_CAPABILITIES = {
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_NET_ADMIN",
    "CAP_DAC_OVERRIDE",
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_BPF",
}


def read_text(path):
    try:
        return Path(path).read_text(errors="replace")
    except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
        return None


def namespace_inode(pid, namespace):
    path = PROC / str(pid) / "ns" / namespace

    try:
        return os.stat(path).st_ino
    except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
        return None


def host_namespaces():
    result = {}

    for namespace in NAMESPACES:
        result[namespace] = namespace_inode(1, namespace)

    return result


def process_namespaces(pid):
    result = {}

    for namespace in NAMESPACES:
        result[namespace] = namespace_inode(pid, namespace)

    return result


def namespace_differences(pid, host_ns):
    differences = []

    process_ns = process_namespaces(pid)

    for namespace in NAMESPACES:
        proc_inode = process_ns.get(namespace)
        host_inode = host_ns.get(namespace)

        if proc_inode is None or host_inode is None:
            continue

        if proc_inode != host_inode:
            differences.append(namespace)

    return differences


def parse_status(pid):
    data = read_text(PROC / str(pid) / "status")

    if not data:
        return {}

    result = {}

    for line in data.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()

    return result


def get_username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def get_uid(status):
    try:
        return int(status["Uid"].split()[0])
    except (KeyError, ValueError, IndexError):
        return None


def get_cmdline(pid):
    try:
        data = (PROC / str(pid) / "cmdline").read_bytes()

        if not data:
            return ""

        return data.replace(b"\x00", b" ").decode(errors="replace").strip()

    except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
        return ""


def decode_capabilities(cap_hex):
    if not cap_hex:
        return []

    try:
        value = int(cap_hex, 16)
    except ValueError:
        return []

    result = []

    for bit, name in CAPABILITIES.items():
        if value & (1 << bit):
            result.append(name)

    return result


def get_cgroup(pid):
    data = read_text(PROC / str(pid) / "cgroup")

    if not data:
        return ""

    return data.strip()


def detect_runtime(cgroup):
    cgroup_lower = cgroup.lower()

    indicators = {
        "docker": "Docker",
        "kubepods": "Kubernetes",
        "containerd": "containerd",
        "libpod": "Podman",
        "podman": "Podman",
        "lxc": "LXC",
        "machine.slice": "systemd-machine",
    }

    for indicator, runtime in indicators.items():
        if indicator in cgroup_lower:
            return runtime

    return None


def calculate_container_score(namespace_diff, runtime):

    # This is intentionally heuristic.

    # Different namespace != automatically container.
    # systemd services may also use namespace isolation.

    score = 0

    if "pid" in namespace_diff:
        score += 3

    if "mnt" in namespace_diff:
        score += 2

    if "net" in namespace_diff:
        score += 2

    if "uts" in namespace_diff:
        score += 1

    if "ipc" in namespace_diff:
        score += 1

    if runtime:
        score += 4

    return score


def classify_container(score):
    if score >= 6:
        return "HIGH"

    if score >= 3:
        return "MEDIUM"

    return "LOW"


def inspect_process(pid, host_ns):
    status = parse_status(pid)

    if not status:
        return None

    uid = get_uid(status)

    name = status.get("Name", "?")

    capabilities = decode_capabilities(
        status.get("CapEff")
    )

    interesting_caps = [
        cap for cap in capabilities
        if cap in INTERESTING_CAPABILITIES
    ]

    namespace_diff = namespace_differences(pid, host_ns)

    cgroup = get_cgroup(pid)

    runtime = detect_runtime(cgroup)

    score = calculate_container_score(
        namespace_diff,
        runtime
    )

    seccomp = status.get("Seccomp", "?")
    no_new_privs = status.get("NoNewPrivs", "?")

    findings = []

    if uid == 0:
        findings.append("runs-as-root")

    if "CAP_SYS_ADMIN" in capabilities:
        findings.append("CAP_SYS_ADMIN")

    if "CAP_SYS_PTRACE" in capabilities:
        findings.append("CAP_SYS_PTRACE")

    if "CAP_SYS_MODULE" in capabilities:
        findings.append("CAP_SYS_MODULE")

    if seccomp == "0":
        findings.append("seccomp-disabled")

    if no_new_privs == "0":
        findings.append("no-new-privs-disabled")

    return {
        "pid": pid,
        "name": name,
        "user": get_username(uid) if uid is not None else "?",
        "uid": uid,
        "cmdline": get_cmdline(pid),
        "container": classify_container(score),
        "container_score": score,
        "runtime": runtime,
        "different_namespaces": namespace_diff,
        "capabilities": capabilities,
        "interesting_capabilities": interesting_caps,
        "seccomp": seccomp,
        "no_new_privs": no_new_privs,
        "cgroup": cgroup,
        "findings": findings,
    }


def enumerate_processes():
    host_ns = host_namespaces()

    processes = []

    for entry in PROC.iterdir():
        if not entry.name.isdigit():
            continue

        pid = int(entry.name)

        process = inspect_process(pid, host_ns)

        if process:
            processes.append(process)

    return sorted(processes, key=lambda x: x["pid"])


def check_socket(path):
    result = {
        "path": path,
        "exists": False,
        "socket": False,
        "writable": False,
    }

    try:
        st = os.stat(path)

        result["exists"] = True
        result["socket"] = stat.S_ISSOCK(st.st_mode)
        result["writable"] = os.access(path, os.W_OK)

    except OSError:
        pass

    return result


def check_container_sockets():
    paths = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/run/podman/podman.sock",
        "/var/run/crio/crio.sock",
    ]

    return [
        check_socket(path)
        for path in paths
    ]


def print_table(processes, containers_only=False):
    print(
        f"{'PID':<8}"
        f"{'USER':<15}"
        f"{'PROCESS':<22}"
        f"{'CONTAINER':<12}"
        f"{'RUNTIME':<14}"
        f"{'NAMESPACES':<25}"
        f"FINDINGS"
    )

    print("-" * 120)

    for proc in processes:

        if containers_only and proc["container"] == "LOW":
            continue

        namespaces = ",".join(
            proc["different_namespaces"]
        ) or "-"

        findings = ",".join(
            proc["findings"]
        ) or "-"

        runtime = proc["runtime"] or "-"

        print(
            f"{proc['pid']:<8}"
            f"{proc['user']:<15}"
            f"{proc['name']:<22}"
            f"{proc['container']:<12}"
            f"{runtime:<14}"
            f"{namespaces:<25}"
            f"{findings}"
        )


def print_socket_findings(sockets):
    print("\nContainer control sockets")
    print("-" * 70)

    for socket in sockets:

        if not socket["exists"]:
            continue

        status = []

        if socket["socket"]:
            status.append("socket")

        if socket["writable"]:
            status.append("WRITABLE")

        print(
            f"{socket['path']:<45} "
            + ", ".join(status)
        )


def logo():
    print("""
▀▀▀▀▀▀▓▓▄ ▀▀▀▀▀▀▓▓▀ ▀▀▀▀▀▀▓▓▀ ▀▀▀▀▀▀▓▓▄ ▀▀▀▀▀▀▓▓▄ ▀▀▓▓▓▀▀ ▀▀▀▀▀▀▓▓▄
▒▒▒▀▀▀▒▒▄ ▒▒▒▀▀ ▀   ▒▒▒ █ ▀   ▒▒▒ █ ▒▒▓ ▒▒▒ █ ▒▒▒ █ ▒▒▒ █ ▒▒▒▀▀▀▒▒▄
░░░ █ ░░░ ░░░ ▀ ░░░ ░░░ ▀ ░░░ ░░░ ▀ ░░░ ░░░ █ ░░░ █ ░░░ █ ░░░ █ ░░░
▀▀▀   ▀▀▀  ▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀  ▀▀▀   ▀▀▀   ▀▀▀   ▀▀▀   ▀▀▀
                                                        by infrar3d
""")

def main():
    
    logo()

    parser = argparse.ArgumentParser(
        description=
        "Linux process/container namespace reconnaissance tool"
    )

    parser.add_argument(
        "--containers-only",
        action="store_true",
        help="Only display processes likely running in containers",
    )

    parser.add_argument(
        "--json",
        dest="json_file",
        help="Export complete results to JSON",
    )

    args = parser.parse_args()

    processes = enumerate_processes()

    sockets = check_container_sockets()

    print_table(
        processes,
        containers_only=args.containers_only
    )

    print_socket_findings(sockets)

    if args.json_file:
        output = {
            "processes": processes,
            "container_sockets": sockets,
        }

        with open(args.json_file, "w") as file:
            json.dump(
                output,
                file,
                indent=4
            )

        print(
            f"\n[+] Results written to {args.json_file}"
        )


if __name__ == "__main__":
    main()