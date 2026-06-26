# HDN Linux

HDN Linux is a work-in-progress Linux kernel hardening patchset for building a
daily-driver distro that keeps security policy mostly invisible to normal users:
secure defaults, graphical/admin-brokered privileged actions, and no expectation
that users manage drivers or hardening knobs from a terminal.

The current patch is carried as a generated diff against upstream Linux
`7.0.12`.

## Repository Layout

- `patches/hdn-linux-7.0.12.patch`: current generated patch against Linux
  `7.0.12`.
- `docs/KERNEL_HARDENING_DESIGN.md`: design notes and hook map.
- `docs/HDN_GRSEC_EQUIVALENCE.md`: adversarial feature comparison and current
  gap tracking.
- `LICENSE`: GPL-2.0, matching the Linux kernel patch licensing requirement.

## Current Status

This is not a finished distro kernel yet. Current rough parity estimates:

- Strict grsecurity/PaX-style patch feature parity: about 38%.
- Practical daily-driver hardening equivalence: about 61%.

Recent coverage includes signed/sealed HDN policy, authority-gated BPF/perf/proc
disclosure, module admission hardening, read-only mount controls, object policy
rules, chroot restrictions, TPE-style execution controls, IPC/socket/device
hardening, privileged-exec restrictions, RWX/textrel/exec-stack controls,
thread-stack placement randomization, proc-visible kernel symbol redaction,
expanded BPF metadata/query gating, and broad audit/event decoding.
USB monitor capture is now gated separately from USB attach so device brokers
do not implicitly gain traffic-sniffing authority. Memfd defaults are now
locked to enforced noexec mode, including rejection of explicit executable
memfd creation. io_uring SQPOLL setup is now behind the restricted-operation
authority alongside other high-risk io_uring registrations. Upstream protected
path sysctls are now locked at hardened floors instead of merely defaulted on.
The dmesg restriction sysctl is also locked at the restricted value, so kernel
log disclosure cannot be re-enabled by a later sysctl write. Legacy TIOCSTI is
forced off, line-discipline autoload is disabled, and neither TTY sysctl can be
turned back on while TTY injection hardening is active.

The largest remaining gaps are richer RBAC/userspace integration, full desktop
and recovery UI around the admin broker, distro package/update wiring, deeper
internal symbol hiding, and large PaX-style compiler/architecture mitigation
families.

## Apply The Patch

Fetch upstream Linux `7.0.12`, then apply:

```sh
tar -xf linux-7.0.12.tar.xz
cd linux-7.0.12
patch -p1 < ../hdn-linux/patches/hdn-linux-7.0.12.patch
```

## Build Smoke

The development tree is currently built out-of-tree:

```sh
make O=/path/to/build olddefconfig
make O=/path/to/build -j"$(nproc)" bzImage modules
```

The hardening smoke suite in the development tree is run under QEMU. Latest
local result before this publication checkpoint:

```text
QEMU hardening smoke: 771/771 pass
```

Patch artifact at this checkpoint:

```text
patch: patches/hdn-linux-7.0.12.patch
lines: 56,334
bytes: 1,651,134
sha256: 3ad9067cbf45e46bde12c598302f3c550d55ff22951bf3d69afccb4a0dbd3c45
```

## Development Rule

The patch artifact is generated from a clean upstream Linux tree and an HDN
working tree. Functional changes should land in the working tree first, pass the
targeted build/smoke coverage for the touched surface, then regenerate
`patches/hdn-linux-7.0.12.patch` and push a checkpoint commit.
