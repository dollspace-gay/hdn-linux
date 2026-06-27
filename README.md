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

- Strict grsecurity/PaX-style patch feature parity: about 22-24%.
- HDN intended hardening surface: about 53%.
- Practical daily-driver hardening equivalence: about 71%.

Recent coverage includes signed/sealed HDN policy, authority-gated BPF/perf/proc
disclosure, module admission hardening, read-only mount controls, object policy
rules including split setid-bit, incoming rename-target, and hardlink target
controls plus AF_UNIX connect, bind, listen, accept, datagram send, and datagram
receive controls, recursive tree false-positive proofs for operation and
target-directory rules, `deny-find` ordinary-open hiding, preopened descriptors,
fd receive, and mount topology, including split `move_mount` source controls,
exec-profile inheritance,
profile-scoped umask floors and resource ceilings, chroot restrictions,
TPE-style execution controls,
IPC/socket/device hardening,
privileged-exec restrictions, RWX/textrel/exec-stack controls, thread-stack
placement randomization, proc-visible kernel symbol redaction, expanded BPF
metadata/query gating, and broad audit/event decoding.
Authorized `kernel.modprobe` writes now also validate the helper path as an
absolute, symlink-free, root-owned executable through non-writable ancestry.
Upstream one-way module and kexec load disable sysctls are reported in sealed
status and smoked for irreversible tightening after product policy flips them.
One-argument `request_module(name)` calls now route exact module names instead
of interpreting caller-provided aliases as printf format strings.
Authorized modprobe helpers also receive bounded HDN context through
`HDN_MODULE_REQUEST`, `HDN_MODULE_UID`, `HDN_MODULE_EUID`, and
`HDN_MODULE_PROFILE`.
USB monitor capture is now gated separately from USB attach so device brokers
do not implicitly gain traffic-sniffing authority. Memfd defaults are now
locked to enforced noexec mode, including rejection of explicit executable
memfd creation. io_uring SQPOLL setup is now behind the restricted-operation
authority alongside other high-risk io_uring registrations, and
`kernel.io_uring_disabled` can only be tightened until reboot. Upstream protected
path sysctls are now locked at hardened floors instead of merely defaulted on.
The dmesg restriction sysctl is also locked at the restricted value, so kernel
log disclosure cannot be re-enabled by a later sysctl write. Profile policy
also gates `/dev/kmsg` writes separately from log reads, so services can be
allowed to inject log records without receiving kernel-log disclosure. Legacy
TIOCSTI is forced off, line-discipline autoload is disabled, and neither TTY sysctl can be
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
Its optional compatibility view reports stable `compat_*` hardening-family keys
derived from sealed HDN status bits for distro tooling that wants coarse
feature-state checks without depending on raw kernel labels. That view now
groups memory initialization, allocator, compiler, stack, and kernel
W^X/page-table families alongside the higher-level policy and disclosure
families.
`hdn-control-center` now gives settings panels and desktop shells one
product-facing status/action/policy entry point above `hdn-status`,
`hdn-desktop-daemon`, and `hdn-policy-daemon`. `hdn-policy-workflow` now gives
support tools and developer-mode UI a root-owned named workflow for policy
learning, candidate policy generation, unsigned binary policy compilation, and
brokered signed policy commit above `hdn-policy-learn`, `hdn-policy-merge`,
the policy compiler, and `hdn-admin-broker`, while `hdn-policy-daemon` gives
product UI an allowlisted root-side facade above those workflows. Commit
preflight now routes through the same `hdn-control-center --dry-run policy
commit WORKFLOW` and `hdn-policy-daemon --dry-run commit WORKFLOW` path so UI
code can validate the approved broker route without installing a policy; the
daemon stdio protocol also accepts `dry-run commit WORKFLOW` for supervised
settings-panel backends.
Other-user proc task visibility now has grouped proc mount compatibility plus
an HDN-native global task-view group for proc, pidfd, and proc task-directory
mode visibility.
Proc memory-map hardening now also denies cross-process `/proc/<pid>/pagemap`
reads and global `/proc/kpage*` page-monitor metadata without disclosure
authority while preserving `/proc/self/pagemap` compatibility.
Sensitive sysfs kernel metadata such as `/sys/kernel/vmcoreinfo`,
`/sys/kernel/notes`, and `/sys/kernel/boot_params/data` now requires the
sysfs-read authority and is hidden from restricted directory enumeration, while
ordinary device-discovery sysfs remains visible.
The exploit-mitigation baseline also enables and enforces upstream page-table
checking on supported architectures, with sealed status and QEMU coverage.

The largest remaining gaps are richer RBAC/userspace integration beyond the
current policy workflow/daemon facade, full desktop and recovery UI around the
admin broker, final image-specific update wiring, deeper internal symbol
hiding, and PaX-style compiler/architecture mechanisms beyond the
upstream-equivalent families already grouped in status.

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
QEMU hardening smoke: 966/966 pass
```

Patch artifact at this checkpoint:

```text
patch: patches/hdn-linux-7.0.12.patch
lines: 66,974
bytes: 1,991,776
sha256: 2cb4f9444b1ca8695b262bc9e7aff0cddb0c531a9ba953726cf171ed87e470c0
```

## Development Rule

The patch artifact is generated from a clean upstream Linux tree and an HDN
working tree. Functional changes should land in the working tree first, pass the
targeted build/smoke coverage for the touched surface, then regenerate
`patches/hdn-linux-7.0.12.patch` and push a checkpoint commit.
