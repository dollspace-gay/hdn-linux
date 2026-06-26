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
- Practical daily-driver hardening equivalence: about 65%.

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
turned back on while TTY injection hardening is active. Yama is now part of the
baseline and `kernel.yama.ptrace_scope` cannot be lowered below relational
mode. Setuid coredumps are locked off through `fs.suid_dumpable=0`, so
privileged-helper core modes cannot be globally enabled after boot.
Low-address mmap protection is now locked at a 64 KiB floor through
`vm.mmap_min_addr`, with QEMU coverage for failed lowering and unprivileged
fixed low-address mmap denial.
Unprivileged userfaultfd kernel-fault handling is now unavailable by
construction or locked behind `vm.unprivileged_userfaultfd=0`, while
user-mode-only userfaultfd use remains available when the syscall is enabled.
The shipped ROFS image list now has explicit `required` and `optional`
mount entries, with `/usr` as the required sealed base image surface and
common boot/app extension mountpoints sealed when present. Package/update hook
templates now cover APT/dpkg, pacman/libalpm, DNF 4, DNF5/libdnf5, and systemd
image sealing through stable `hdn-package-hook` actions, and the hardening
helper `Makefile` now has a packaging install target for helper binaries,
root-owned config templates, and those hook snippets. The event decoder now
also names common packed event object details for exec arguments, signals,
resource limits, time changes, USB, coredumps, and socket context, so UI and
log consumers do not need to unpack those raw integers themselves. A new
`hdn-status` helper gives desktop daemons, settings panels, support tools, and
recovery UI stable product-facing `key=value` status with policy readiness,
mitigation counts, audit-flood state, and decoded audit-flood names.
`hdn-control-center` now gives settings panels and desktop shells one
product-facing status/action entry point above `hdn-status` and
`hdn-desktop-daemon`.
Sensitive sysfs kernel metadata such as `/sys/kernel/vmcoreinfo` now requires
the sysfs-read authority and is hidden from restricted directory enumeration,
while ordinary device-discovery sysfs remains visible.
The exploit-mitigation baseline also enables and enforces upstream page-table
checking on supported architectures, with sealed status and QEMU coverage.

The largest remaining gaps are richer RBAC/userspace integration, full desktop
and recovery UI around the admin broker, final image-specific update wiring,
deeper internal symbol hiding, and large PaX-style compiler/architecture
mitigation families.

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
QEMU hardening smoke: 796/796 pass
```

Patch artifact at this checkpoint:

```text
patch: patches/hdn-linux-7.0.12.patch
lines: 59,223
bytes: 1,741,344
sha256: e6d2e110f6f65b168ed752f87f553952560a0a929af2c540a42ae8ba515c66eb
```

## Development Rule

The patch artifact is generated from a clean upstream Linux tree and an HDN
working tree. Functional changes should land in the working tree first, pass the
targeted build/smoke coverage for the touched surface, then regenerate
`patches/hdn-linux-7.0.12.patch` and push a checkpoint commit.
