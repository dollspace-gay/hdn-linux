# Name Pending: Linux Kernel Hardening Design

## Purpose

This document describes a cleaner architecture for a Linux kernel hardening suite with grsec-class security outcomes but original structure, names, code, and policy model.

The goal is not to create a source-compatible replacement for grsecurity, PaX, gradm, RAP, or any related tooling. The goal is to build a hardened Linux platform where the kernel enforces strong invariants, the distro owns the policy layer, and normal users experience security as part of the OS rather than as a thing they configure.

The working design principle is:

> Touch core kernel paths only to install stable hardening contract points. Keep product policy, desktop behavior, authorization prompts, and learning/audit logic outside those paths.

## Product Goals

- Daily-driver OS behavior for normal people.
- Secure-by-default kernel and userland without requiring terminal use.
- No routine driver, privilege, or policy fiddling by end users.
- Admin actions use normal graphical prompts.
- Security policy is expressed in OS concepts: apps, drivers, accounts, developer mode, recovery, system updates.
- Kernel hardening is quietly present and visible only when it blocks something important.
- Advanced users can inspect and override policy, but overrides are explicit, logged, reversible, and time-scoped where possible.

## Security Goals

- Reduce local privilege escalation reliability.
- Reduce kernel exploit reliability.
- Reduce useful information disclosure.
- Restrict writable/executable memory transitions.
- Restrict dangerous kernel attack surfaces by default.
- Enforce signed/trusted code admission for privileged components.
- Contain untrusted apps, interpreters, scripts, plugins, and developer tools.
- Make policy changes transactional and auditable.
- Preserve reliable recovery from bad policy without dropping normal users into a raw shell.

## Non-Goals

- Source compatibility with gradm policies.
- Public compatibility with grsecurity, PaX, RAP, or related naming.
- A giant patch where policy decisions are hand-wired throughout unrelated subsystems.
- A security model that expects the user to understand kernel internals.
- An app store or packaging model in this document. This design only defines the kernel hardening and policy enforcement architecture that such systems would consume.
- Perfect defense against compromised firmware, malicious hardware, full physical access without disk protection, or a hostile kernel build environment.

## Threat Model

The design assumes attackers may control:

- A normal unprivileged process.
- A malicious document, browser renderer, game, package script, plugin, or interpreter workload.
- A compromised app with user-level permissions.
- A local developer workload trying to escape intended boundaries.
- A malicious or vulnerable setuid/setgid program.
- A vulnerable system service.
- A malicious unsigned or untrusted driver package attempting admission.

The design assumes attackers may attempt:

- Kernel memory corruption.
- ROP/JOP/COP style control-flow attacks.
- Writable/executable memory abuse.
- Kernel pointer and layout discovery.
- Abuse of BPF, perf, ptrace, userfaultfd, user namespaces, io_uring, debugfs, tracefs, procfs, sysfs, module loading, kexec, raw I/O, and similar attack surfaces.
- Credential transition abuse.
- Policy confusion across exec, interpreter, script, and helper boundaries.
- Persistence through startup units, privileged helpers, kernel modules, and policy changes.

The design does not claim complete protection if:

- The kernel itself is intentionally built with hostile changes.
- Secure Boot or measured boot roots are disabled by the platform owner.
- The recovery authority is compromised.
- An administrator intentionally installs a fully trusted malicious kernel or driver.

## Design Principles

### 1. Mechanism and Policy Are Separate

Kernel code enforces hard invariants and consumes compact decisions. It should not know the distro's desktop policy language, human-readable app categories, or package-manager concepts.

The policy compiler and authorization broker translate product intent into sealed kernel objects.

### 2. Transitions Matter More Than Steady State

Most security state changes at a small number of transitions:

- `execve`
- credential changes
- multithreaded setxid propagation
- namespace creation
- mount changes
- memory protection changes
- module and firmware admission
- BPF/perf/debug feature enablement
- privilege broker approvals
- package install, update, and rollback

The design concentrates checks at these transitions and caches results in per-task, per-mm, and per-namespace profiles.

### 3. Hot Paths Use Sealed Profiles

Hot kernel paths should not do path-heavy RBAC lookups or parse policy. They should consult immutable or RCU-protected profile state already attached to the current task, mm, credential, namespace, file, or mount.

### 4. Deny and Rewrite Are Both First-Class

Classic allow/deny hooks are not enough. Some hardening needs to rewrite requested behavior:

- Strip `PROT_EXEC`.
- Strip `VM_MAYEXEC`.
- Force randomized address selection.
- Reject fixed mappings unless explicitly allowed.
- Convert a dangerous mode into a safer mode.
- Downgrade a debug interface to metadata-only.

The mediation layer therefore returns structured decisions, not just `0` or `-EACCES`.

### 5. Sealing Is a Kernel Primitive

The kernel has phases:

```text
boot mutable -> init mutable -> policy mutable -> sealed runtime
```

Objects declare when they may be mutated. After the allowed phase, mutation is rejected or the backing memory becomes read-only.

### 6. Attack Surface Is an Authority System

Dangerous features are not scattered sysctls. They are named authorities:

- `AUTH_BPF_LOAD`
- `AUTH_PERF_OPEN`
- `AUTH_USERNS_CREATE`
- `AUTH_MODULE_LOAD`
- `AUTH_MODULE_AUTOLOAD`
- `AUTH_KEXEC_LOAD`
- `AUTH_PTRACE`
- `AUTH_PTRACE_EXEC_READ`
- `AUTH_SIGNAL`
- `AUTH_PROCESS_MEMORY`
- `AUTH_MEMORY_MIGRATE`
- `AUTH_PROCESS_FD`
- `AUTH_RAW_IO`
- `AUTH_DEBUGFS`
- `AUTH_PROC_DISCLOSE`
- `AUTH_PROC_TASK_VIEW`
- `AUTH_SYSFS_MUTATE`
- `AUTH_SYSFS_READ`
- `AUTH_IO_URING_RESTRICTED_OP`
- `AUTH_KERNEL_LOG_READ`
- `AUTH_KERNEL_LOG_WRITE`
- `AUTH_FIRMWARE_LOAD`
- `AUTH_IPC_ADMIN`
- `AUTH_TTY_INJECT`
- `AUTH_FUSE_MOUNT`
- `AUTH_ROFS_RELAX`
- `AUTH_USB_ATTACH`
- `AUTH_USB_MONITOR`
- `AUTH_SOCKET_CREATE`
- `AUTH_SOCKET_CONNECT`
- `AUTH_SOCKET_SERVER`
- `AUTH_TIME_ADMIN`
- `AUTH_RESOURCE_ADMIN`
- `AUTH_BLOCK_DEVICE_ACCESS`
- `AUTH_BLOCK_DEVICE_ADMIN`

Each authority has default policy, audit behavior, optional prompt behavior, and emergency override behavior.

Process-accounting audit is intentionally not an authority. Profiles opt into
it with `AUDIT_PROCESS_ACCOUNT`, which records `PROCESS_ACCOUNT` allow-audit
events for process-level exits and stores the raw kernel exit status in the
event object field.

Privileged exec lineage is also not an authority. Once an mm has passed through
a setuid, setgid, secureexec, or file-capability transition, HDN carries that
lineage across later execs. If `fs.suid_dumpable` is disabled and the lineage
later tries to produce a `SIGXCPU` or `SIGXFSZ` coredump after becoming dumpable
again, the kernel blocks the core and records a `COREDUMP` denial. This keeps
the hardening effect invisible to normal users while closing a privileged-helper
data-exposure path.

Exec argument telemetry is not an authority. When exec audit is enabled, HDN
records a second successful-exec audit event named `EXEC_ARGS` whose object
field packs `(argc << 32) | envc`. This gives policy tooling an exec-argument
shape signal without copying raw argument strings into kernel logs.

Proc IP attribution is intentionally not an authority. HDN records accepted
IPv4 TCP peer addresses as kernel-owned proc metadata and exposes them through
owner-readable `/proc/<pid>/ipaddr`, with the address handed to the next forked
child and cleared from the accepting parent. If that process opens a local TCP
connection, HDN records the established connection tuple long enough for the
local acceptor to consume it and keep attributing work to the original peer.
AF_UNIX stream listeners get the same carried attribution through the accepted
server-side socket.

Proc task visibility also honors upstream procfs group mounts. A procfs
instance mounted with `hidepid=1/2,gid=<gid>` lets members of that proc mount
group see other users' task directories on that mount without granting the
broader `AUTH_PROC_TASK_VIEW` or `AUTH_PROC_DISCLOSE` authorities.
Product images can also set `SECURITY_HARDENING_PROC_TASK_GID` or boot with
`hdn.proc_task_gid=<gid>` to give one global group the same task-view and
pidfd-open visibility without broader proc disclosure.
`SECURITY_HARDENING_PROC_TASK_MODES` uses that configured group to publish
public proc task directories as owner-and-task-view-group traversable instead
of world-traversable, so cached inode metadata and fresh `stat(2)` results
match the task-visibility policy.

Proc memory-map redaction is a build-time mitigation with a policy bypass, not
a prompt. With `SECURITY_HARDENING_PROC_MEMMAP`, reads of another address
space's `/proc/<pid>/maps`, `smaps`, `smaps_rollup`, `numa_maps`, and `stat`
hide ASLR-sensitive addresses unless the caller has `AUTH_PROC_DISCLOSE`.
Cross-process `/proc/<pid>/pagemap` reads and the binary `PROCMAP_QUERY` ioctl
are denied without disclosure authority so they cannot become lower-friction
address or page-state oracles. Self and same-thread-group reads remain
compatible. `/proc/ioports` and `/proc/iomem` retain resource names for
hardware inventory, but their address ranges collapse to zero unless a capable
caller also has `AUTH_PROC_DISCLOSE`. Global page-monitoring metadata in
`/proc/kpagecount`, `/proc/kpageflags`, and `/proc/kpagecgroup` is denied
without disclosure authority. The same mitigation also caps privileged execs to
a 512 KiB copied argv/env stack and an 8 MiB stack rlimit, preserving
stack-layout entropy for setuid, setgid, secureexec, and file-capability
helpers without exposing a user-facing knob.

Network blackhole and TCP simultaneous-connect hardening are also intentionally
not authorities. HDN treats them as invisible build-time baseline mitigations:
remote closed-port TCP/UDP/protocol responses are quieted while loopback stays
diagnostic, and crossed-SYN simultaneous open is removed without creating a
desktop prompt. The smoke harness packet-proves the remote behavior by
injecting closed-port TCP and UDP packets through a TUN device.

Anonymous thread-stack placement randomization is also a build-time mitigation,
not a promptable authority. For private anonymous no-hint `MAP_STACK` and
stack-like `MAP_GROWSDOWN` allocations, HDN asks the unmapped-area search to
reserve a small random page-aligned gap when process ASLR is enabled and
`ADDR_NO_RANDOMIZE` is not set. This keeps ordinary pthread-style and legacy
grow-down stack allocation invisible to users while making adjacent
thread-stack layouts less predictable.

### 7. Fail Closed, Recover Deliberately

Runtime security failures fail closed. Product recovery is a separate controlled path:

- signed recovery policy
- offline rollback
- known-good boot profile
- local owner recovery token
- repair UI
- no raw root shell as the default normal-user experience

## High-Level Architecture

```text
+---------------------------------------------------------------+
| Desktop / Settings / Installer / Package Manager / App Store   |
+------------------------------+--------------------------------+
                               |
                               v
+---------------------------------------------------------------+
| System Authorization Broker                                    |
| - graphical prompts                                            |
| - user/admin authentication                                    |
| - typed privileged actions                                     |
| - time-scoped approvals                                        |
+------------------------------+--------------------------------+
                               |
                               v
+---------------------------------------------------------------+
| Policy Compiler and State Manager                              |
| - app identity                                                  |
| - trust database                                                |
| - package/driver provenance                                    |
| - human policy -> compact kernel policy                         |
| - transaction, rollback, audit                                  |
+------------------------------+--------------------------------+
                               |
                               v
+---------------------------------------------------------------+
| Kernel Hardening Interface                                     |
| - profile load/update                                           |
| - authority decisions                                           |
| - sealing state                                                 |
| - audit/event stream                                            |
+------------------------------+--------------------------------+
                               |
                               v
+---------------------------------------------------------------+
| Kernel Enforcement                                             |
| - invariant layer                                               |
| - transition hooks                                              |
| - sealed profiles                                               |
| - authority gates                                               |
| - arch/compiler hardening                                       |
+---------------------------------------------------------------+
```

## Kernel Architecture

The kernel side is split into five components.

### 1. Invariant Layer

The invariant layer enforces rules that should not depend on user policy.

Examples:

- Kernel text is never writable after init.
- Sealed kernel data is not writable after its mutation phase closes, and
  attempted writes to sealed HDN pages are surfaced as invariant events.
- Module memory obeys strict W^X.
- User mappings cannot be writable and executable at the same time unless a sealed profile explicitly grants a narrow exception.
- Kernel pointers are not disclosed to unprivileged users.
- Freed heap memory and stack memory are sanitized according to build policy.
- Kernel stacks use upstream vmapped stack isolation, separated `thread_info`,
  randomized syscall stack offsets, and strong compiler stack protection where
  the architecture supports them.
- Reference counters and size calculations use hardened checked primitives where feasible.
- Usercopy boundaries are checked.
- Dangerous debugging interfaces are unavailable unless a profile grants explicit authority.

This layer should be mostly boring C, compiler flags, arch support, and small hardening helpers.

### 2. Transition Hook Layer

The transition layer exposes explicit hooks where security-relevant state changes.

Required transition classes:

```c
enum hardening_transition {
    HDN_TRANS_EXEC,
    HDN_TRANS_CRED_CHANGE,
    HDN_TRANS_MMAP,
    HDN_TRANS_MPROTECT,
    HDN_TRANS_MODULE_LOAD,
    HDN_TRANS_FIRMWARE_LOAD,
    HDN_TRANS_BPF_LOAD,
    HDN_TRANS_PERF_OPEN,
    HDN_TRANS_PTRACE,
    HDN_TRANS_PTRACE_EXEC_READ,
    HDN_TRANS_USERNS_CREATE,
    HDN_TRANS_MOUNT,
    HDN_TRANS_KEXEC_LOAD,
    HDN_TRANS_IO_URING_OP,
    HDN_TRANS_PROCFS_READ,
    HDN_TRANS_SYSFS_WRITE,
    HDN_TRANS_POSIX_MQUEUE_ACCESS,
    HDN_TRANS_TIME_CHANGE,
    HDN_TRANS_RESOURCE_LIMIT,
    HDN_TRANS_BLOCK_DEVICE_ACCESS,
    HDN_TRANS_BLOCK_DEVICE_ADMIN,
    HDN_TRANS_FORK,
};
```

These hooks return structured decisions.

```c
enum hardening_action {
    HDN_ALLOW,
    HDN_DENY,
    HDN_REWRITE,
    HDN_ALLOW_AND_AUDIT,
    HDN_DENY_AND_AUDIT,
};
```

For transitions like `mmap` and `mprotect`, the hook may mutate a request object before the kernel commits it.

```c
struct hdn_mmap_request {
    struct file *file;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long pgoff;
    struct hdn_exec_profile *profile;
};

struct hdn_decision hdn_mmap_rewrite(struct hdn_mmap_request *req);
```

Core `mm/` code remains responsible for memory management. The hardening layer is responsible only for legalizing or rejecting requested protection state.

### 3. Profile Layer

The profile layer attaches compact sealed policy to kernel objects.

Primary profile types:

- `hdn_exec_profile`: attached to `mm_struct` and inherited according to exec rules.
- `hdn_task_profile`: attached to task or credential state.
- `hdn_ns_profile`: attached to namespaces.
- `hdn_mount_profile`: attached to mounts or superblocks where needed.
- `hdn_file_identity`: cached identity/trust result for executable files and privileged helpers.

Conceptual structure:

```c
struct hdn_exec_profile {
    u64 profile_id;
    u64 subject_label;
    u64 trust_level;
    u64 memory_policy;
    u64 syscall_surface;
    u64 namespace_policy;
    u64 debug_policy;
    u64 io_policy;
    u64 authority_mask;
    u64 audit_mask;
};
```

Profiles are:

- immutable after publication
- reference counted or RCU-managed
- loaded through a privileged kernel interface
- versioned
- auditable
- recoverable through signed rollback

### 4. Authority Gate Layer

The authority gate layer centralizes dangerous feature checks.

Instead of each subsystem growing its own hardening policy, subsystems ask a common authority checker:

```c
int hdn_authorize(enum hdn_authority authority,
                  const struct hdn_authority_context *ctx);
```

The context carries only the facts needed for a decision:

```c
struct hdn_authority_context {
    const struct cred *cred;
    const struct file *file;
    const struct path *path;
    const struct task_struct *target;
    u64 operation;
    u64 flags;
};
```

Authority gates should cover:

- BPF program load and privileged helper use.
- perf event access.
- ptrace, explicit process remote-memory operations, and execute-only memory
  read bypass.
- user namespace creation.
- kernel module load.
- one-way global module-load disablement through `kernel.modules_disabled`.
- firmware load.
- kexec.
- one-way global kexec-load disablement through `kernel.kexec_load_disabled`.
- raw I/O, port I/O, and x86 VM86 mode.
- debugfs and tracefs visibility and mutation.
- kernel symbol visibility, user-driven symbol resolution, symbolic pointer
  formatting, and trace symbol formatting, separate from plain tracefs/debugfs
  access.
- procfs disclosure.
- owner-only and sensitive sysfs disclosure plus sysfs mutation.
- kernel log read disclosure and `/dev/kmsg` write injection.
- io_uring operations that expand attack surface, including SQPOLL setup and
  privileged registration families.
- one-way tightening of `kernel.io_uring_disabled` for recovery or image policy.
- new USB device attachment and usbmon capture.
- non-local socket creation, outbound connections, and server-side bind/listen/accept.

### 5. Audit and Event Layer

The kernel emits structured security events. It does not format desktop prompts and does not implement learning mode as a kernel policy language.
Repeated identical event keys are flood-controlled in the kernel so a noisy
denial class cannot continuously evict unrelated records from the fixed event
ring. The burst and window are runtime-tunable through securityfs
`audit_flood_burst` and `audit_flood_window_ms` controls, with policy-admin
authorization and bounded values. Suppression is visible through status
counters; policy learning and rich presentation still belong to userspace.
`hdn-status` is the user-facing status facade: it turns those raw status lines
into stable `key=value` state for settings panels, desktop daemons, support
bundles, and recovery UI, including decoded audit-flood action, authority,
transition, and reason names.
Its optional compatibility view reports `compat_*` feature-family keys derived
from sealed HDN status bits, giving distro tooling a stable way to ask whether
covered hardening families such as symbol hiding, proc/sysfs restriction,
BPF/perf lockdown, memory initialization, allocator hardening, compiler
hardening, stack hardening, kernel W^X/page-table hardening, ROFS, USB,
sockets, IPC, and audit are active without depending on raw kernel labels or
cloning lower-level control names.
`hdn-control-center status` is the stable settings-shell entry point above that
facade, so product UI can ask for status through one branded helper without
parsing securityfs or depending on the raw status helper path.

Event shape:

```text
timestamp
event_id
profile_id
authority
transition
decision
subject identity
object identity
reason code
stable diagnostic fields
```

Userspace consumes these events for:

- graphical notification
- developer diagnostics
- policy learning
- enterprise export
- forensic logging
- harness validation

The reference event reader is `tools/hardening/hdn-event-decode`. It leaves
the kernel record format compact, maps numeric event/action/authority/
transition/reason fields to stable UAPI names, decodes common packed `object`
payloads for exec arguments, signals, resources, time changes, USB, coredumps,
and socket context, and supports decoded expectations such as
`--expect reason=USER_WX_MAPPING` for automation.
`tools/hardening/hdn-policy-learn` consumes the same stable event records for
userspace learning mode: denied profile-authority events become de-duplicated
reviewable `allow` suggestions, selected memory-compatibility denials become
`mem` suggestions, and high-risk identity/invariant failures stay as review
comments for a settings app or support tool instead of becoming broad automatic
bypasses.
`tools/hardening/hdn-policy-merge` is the matching candidate-policy step: it
copies a base text policy, consumes only reviewed `allow` and `mem`
suggestions for profiles already defined in that base, de-duplicates existing
grants, and appends a marked candidate block for later compile/sign/commit.
`tools/hardening/hdn-policy-workflow` puts a root-owned named contract above
those helpers, the policy compiler, and the admin broker so settings panels,
support tools, and developer-mode policy UI can run `learn NAME`,
`candidate NAME`, `compile NAME`, and `commit NAME` without receiving raw
event-log, base-policy, fragment, candidate output, binary policy output, or
signed policy paths. The compile step writes an unsigned payload; signing
remains a product policy step; commit delegates a configured signed policy path
to `hdn-admin-broker policy-commit`.
`tools/hardening/hdn-policy-daemon` is the product-facing root-side facade
above policy-workflow. It allowlists workflow names from a root-owned config,
supports one-shot or stdio operation, accepts one-shot `--dry-run commit NAME`
and stdio `dry-run commit NAME` for broker preflight without policy
installation, and lets `hdn-control-center policy` route settings-panel policy
review and signed commit actions without exposing helper paths.

## Memory Execution Policy

Executable memory is one of the central policy surfaces.

Default rules:

- Anonymous writable/executable mappings are denied.
- File-backed writable/executable mappings are denied.
- `mprotect` cannot add execute permission to memory that was previously writable unless the profile permits it.
- `READ_IMPLIES_EXEC` compatibility is disabled or narrowed for normal applications.
- JIT engines require a profile grant.
- JIT grants are app-specific and may require dual mapping, write-xor-execute discipline, or runtime broker approval.
- Fixed-address executable mappings are denied unless the profile grants a compatibility exception.
- `memfd_create()` defaults to noexec/sealed behavior, explicit executable memfd creation is denied, and the sysctl floor cannot be lowered from enforced noexec mode.
- Trusted executables may carry a versioned HDN ELF memory note for narrow compatibility hints. The note can grant private anonymous exec-after-write, executable-stack ELF mapping, and textrel-style `mprotect` compatibility to that executable only. The flags are copied to the new `mm` during exec and ignored unless the executable is root-owned and not group/world-writable.

Memfd executable state is deliberately not another authority. It is a baseline
kernel invariant because anonymous executable file descriptors are mostly an
exploit/JIT primitive, and legitimate JIT compatibility is already handled by
profile-scoped or trusted-executable memory grants.

Profile options:

```text
MEM_EXEC_NONE
MEM_EXEC_FILE_ONLY
MEM_EXEC_SIGNED_FILE_ONLY
MEM_EXEC_JIT_BROKERED
MEM_EXEC_LEGACY_COMPAT
```

The default desktop profile should allow normal apps, browsers, games, and language runtimes through explicit app policy rather than through global weakening.

## Exec Identity Model

`execve` establishes identity.

The kernel should derive or receive:

- file trust state
- package identity
- signature state
- fs-verity or measured identity where available
- interpreter chain identity
- privilege transition state
- previous profile
- requested domain transition

The result is a sealed `hdn_exec_profile`.

Important cases:

- Native executable.
- Script with interpreter.
- Dynamic linker.
- Setuid/setgid binary.
- File capability binary.
- User-installed app.
- System package binary.
- Developer-built binary.
- Temporary build output.
- App bundle helper.
- Browser renderer.
- Game anti-cheat or driver helper.

Exec policy should be decided at exec time so later hot paths do not need to
resolve complex path ancestry for every process action. The non-root TPE mode
also checks file-backed executable `mmap()` and `mprotect()` transitions so an
unsafe user-controlled path cannot be used as an alternate executable-code
loader.

Trusted execution has two profile-scoped shapes. Strict trusted-path execution
requires the executable and path/mount ancestry to be root-owned and not
group/world-writable. Non-root TPE denies exec and file-backed executable
mapping/protection transitions from non-root-owned executable directories,
world-writable directories, group-writable non-root directories, and
world-writable files. A profile without that flag, or a profile with
`TRUSTED_EXEC_BYPASS`, is the HDN equivalent of a trusted or inverted TPE
group.

## Driver and Module Admission

Kernel modules are product-level privileged code.

Default rules:

- Unsigned modules do not load.
- Unknown signed modules do not load without broker approval.
- Kernel-triggered module autoload does not run modprobe without a profile
  grant.
- One-argument `request_module(name)` calls are exact module aliases, not
  printf format strings; formatted calls must pass explicit varargs.
- Authorized modprobe helpers receive bounded HDN context in the environment:
  requested alias, requesting uid/euid, and current HDN profile id.
- The `kernel.modprobe` helper path cannot be changed unless the caller is in
  policy-admin context and has `AUTH_MODULE_AUTOLOAD`, preventing restricted
  root profiles from redirecting future autoload execution.
- Authorized helper-path writes must still be empty or point to an absolute,
  symlink-free, root-owned executable through non-group/world-writable ancestry.
- Product policy can irreversibly close later module loads for the boot through
  upstream `kernel.modules_disabled`; HDN reports that lockout in sealed status.
- Approval records exact module identity, signer, version, target kernel ABI, and package source.
- Approval can be one-shot, until reboot, until update, or permanent.
- Permanent approval is stored as a signed local policy transaction.
- Revocation is supported.
- Module load failure should produce a normal UI path, not a terminal instruction.

The kernel gate is simple:

```text
module identity + signer + current boot state + profile -> allow/deny
module alias + profile -> allow/deny autoload
```

The product handles user interaction.

## Attack Surface Policy

The OS ships with profiles such as:

```text
Standard User
Developer Mode Off
Developer Mode On
System Service
Browser Renderer
Packaged App
Game
Virtualization Host
Container Host
Recovery
```

Each profile maps to authority grants.

Example:

```text
Standard User:
  BPF load: deny
  perf kernel access: deny
  user namespaces: restricted
  ptrace: same-profile only
  debugfs: hidden
  kernel logs: reads redacted, writes denied
  module load: deny

Developer Mode On:
  BPF load: brokered or group-limited
  perf: user-only by default, kernel with approval
  user namespaces: allow with resource limits
  ptrace: same-user developer sessions
  debugfs: metadata-only unless approved
  kernel logs: rate-limited reads and brokered writes by default
  module load: signed local dev modules only with approval
```

Developer mode is not a boolean that disables hardening. It is a separate policy profile with explicit grants.

## Privilege Broker Integration

The kernel hardening suite depends on a userspace authorization broker for human approval.

The broker handles typed operations:

```text
Install signed driver
Enable developer mode
Allow debugger for this app
Allow profiler until logout
Allow local virtualization features
Trust this app bundle
Permit JIT for this runtime
Rollback security policy
```

The broker must never ask users to approve raw commands like:

```text
run this kernel knob
execute this gradm command
write this sysctl
disable this mitigation
```

The prompt should name the actual intent and consequence.

The current tree includes the first backend facade,
`tools/hardening/hdn-admin-broker`. It is intentionally not a desktop prompt:
the prompt daemon authenticates the user and calls the broker after approval.
The broker accepts typed intents for product read-only mount apply,
read-only mount transactions, signed policy commit, and policy rollback. It
execs the ROFS helpers directly, requires absolute privileged paths, and avoids
shell command approval. It also loads a root-owned product allowlist
(`admin-broker.conf`) and fails closed unless the requested mountpoint, worker,
read-only mount list, policy path, or rollback intent is approved there. ROFS
apply lists are still opened by the helper under safe-file rules: regular,
root-owned, not group/world writable, and not symlinked. QEMU proves both sides
of the `rofs-transaction` path: missing or writable broker allowlists fail
closed, an unapproved worker is denied before it can update the sealed mount,
and an approved worker runs under a parent-scoped broker profile that
transitions into the narrow ROFS transaction profile. QEMU also proves the
brokered ROFS apply path by denying an unapproved list, refusing an
approved-but-writable list in the helper, and applying a safe approved list
through the narrow helper. QEMU proves the brokered policy path by committing a
signed policy from a product-approved policy directory, rolling back to the
previous generation, and denying an otherwise valid signed policy outside the
approved policy directory without staging it or changing the active generation.
The broker also has an optional approval-token handoff for desktop prompt
daemons. When `require-approval-token` is set, the broker refuses typed intents
unless the caller supplies `--approval-token` pointing under an approved
`approval-token-dir`. The token must be a root-owned, one-link regular file,
not group/world accessible, not symlinked, and must contain `HDN_APPROVAL_V1`
plus the exact `intent=<typed-intent>` line and a
`expires-monotonic-ms=<deadline>` line. The deadline is compared against
`CLOCK_MONOTONIC`, so prompt daemons can issue short-lived approvals without
depending on wall-clock trust. `hdn-approval-token` is the root-side issuer for
the product prompt daemon: it accepts only known typed intents, requires a
root-owned 0700 approval directory, creates root-owned 0600 tokens, and prints
the token path for the broker call. Real dispatch consumes the token before
running the privileged helper; dry-run validates without consuming so tests and
prompt daemons can exercise the path. QEMU proves missing tokens, unsafe
tokens, wrong-intent tokens, and expired tokens fail closed, proves the issuer
rejects unknown intents and creates a broker-valid token, proves a valid token
authorizes the intended typed dry-run path, and proves a real token-backed ROFS
transaction consumes the token, reseals the mount, and rejects replay.
`hdn-prompt-dispatch` is the root-side post-auth facade above that token
handoff. The desktop authenticator approves a named product action, then calls
this helper instead of constructing token and broker command lines itself. A
root-owned prompt-action config maps action names to broker intents and
arguments; the helper issues a short-lived approval token and execs the broker
with `--approval-token`. QEMU proves unknown prompt actions and unsafe prompt
configs fail closed, and proves an approved named package-update action reaches
the strict token-required broker, updates the sealed product mount, and reseals
it read-only.
`hdn-prompt-describe` is the read-only desktop prompt metadata facade next to
that dispatch path. The GUI asks for a named product action before
authentication and receives stable title/message/consequence/risk fields from
a root-owned product manifest instead of deriving prompt text from raw broker
arguments. It never issues tokens or runs privileged backends. QEMU proves
unknown prompt metadata actions and unsafe metadata configs fail closed, and
proves an approved package-update action emits the expected stable metadata.
`hdn-prompt-session` is the root-side session facade for products that want the
backend to enforce the complete UAC-style order. It obtains metadata through
`hdn-prompt-describe`, passes that metadata to a product authenticator over
stdin, and calls `hdn-prompt-dispatch` only after the authenticator exits
successfully. The root-owned session config selects absolute helper paths and
does not invoke a shell. QEMU proves unknown actions, unsafe session configs,
failed authentication, and missing graphical sessions stop before dispatch,
and proves an approved package-update session reaches the strict
token-required broker, updates the sealed product mount, and reseals it
read-only. `hdn-auth-prompt` is the starter desktop authenticator for this
contract: it validates root-owned prompt metadata from stdin, displays an
allow/cancel dialog through common desktop prompt helpers, and fails closed
when no graphical session is available.
`hdn-prompt-portal` is the product desktop entrypoint above that session
contract. Desktop shells, settings panels, and update notifiers call a branded
action from a root-owned portal manifest; the portal maps it to a
prompt-session action and never exposes token, broker, or helper command lines
to the caller. QEMU proves unknown desktop actions and unsafe portal configs
fail closed, and proves an approved desktop action reaches the authenticated
prompt-session path, updates the sealed product mount, and reseals it
read-only.
`hdn-desktop-action` is the stable UI-verb facade above the prompt portal.
Product UI code calls namespaced verbs such as `updates.install` from a
root-owned desktop-action manifest instead of depending on prompt-portal action
names or lower-level helper paths. QEMU proves unknown UI verbs and unsafe
desktop-action configs fail closed, and proves an approved verb reaches the
portal path, authenticates, updates the sealed product mount, and reseals it
read-only.
`hdn-desktop-daemon` is the root-side desktop action service above
`hdn-desktop-action`. It can run one approved verb or stay attached to a
supervised frontend through stdio; its root-owned daemon config allowlists UI
verbs before any dispatch. QEMU proves unknown UI verbs and unsafe daemon
configs fail closed, and proves an approved stdio `updates.install` action
reaches desktop-action, authenticates, updates the sealed product mount, and
reseals it read-only.
`hdn-control-center` is the product-facing command surface above status,
desktop actions, and policy workflows. Settings panels and shells call
`hdn-control-center status` for product health,
`hdn-control-center action DESKTOP_ACTION` for an allowlisted UI verb, or
`hdn-control-center policy COMMAND WORKFLOW` for policy learning, candidate
generation, compile, brokered commit, and `--dry-run policy commit WORKFLOW`
preflight. Its `--stdio` mode accepts `status`, `action DESKTOP_ACTION`,
`policy COMMAND WORKFLOW`, and `dry-run policy commit WORKFLOW` for supervised
settings-panel backends; the helper validates absolute backend paths and safe
action or workflow names and never invokes a shell. QEMU proves one-shot and
stdio status routing, one-shot and stdio unknown UI action denial, approved
one-shot and stdio `updates.install` actions reaching the desktop daemon while
preserving the read-only reseal invariant, stdio rejection of non-commit policy
dry-runs, and an approved compiled policy workflow plus one-shot and stdio
commit preflight reaching the policy daemon.
`hdn-image-seal` is the installer/first-boot/image-updater facade for sealing
the base image. Product config maps stable seal names to ordered brokered
steps such as signed policy commit and read-only mount-list application, so
image tooling calls `hdn-image-seal default` instead of constructing raw broker
commands. The config is root-owned and fails closed if it is missing or
writable. QEMU proves unknown seal names and unsafe configs are denied without
sealing the test mount, proves approved seal dry-run leaves mount state
unchanged, and proves the real approved seal applies a broker-approved
read-only mount list and leaves the mount read-only.
The shipped default read-only list uses `required /usr` for the base image and
`optional` entries for boot, EFI, `/opt`, `/usr/local`, Flatpak, and snapd
mounts so one product config can cover common split-layout images without
failing when an optional filesystem is absent.
`hdn-system-transaction` is the package-manager/image-updater facade above the
broker. Product config maps stable operation names to a mountpoint and worker,
so package tools call `hdn-system-transaction package-update` instead of
constructing broker command lines with raw paths. The config is root-owned and
fails closed if it is missing or writable. QEMU proves unknown operation names
and unsafe configs are denied without changing the sealed mount, and proves an
approved named transaction dry-run preflights the broker route without changing
the sealed mount before the real transaction updates the product mount through
the broker and reseals it read-only.
`hdn-package-hook` is the package-manager hook facade above named system
transactions and image seals. Product config maps stable package-manager hook
names to either `hdn-system-transaction` or `hdn-image-seal`, so package
manager scripts and image builders call `hdn-package-hook package-update`
instead of knowing backend helper paths or broker arguments. The config is
root-owned and fails closed if it is missing or writable. QEMU proves unknown
hook names and unsafe configs are denied without changing the sealed mount,
proves an approved package-update hook dry-run reaches the named system
transaction backend without changing the sealed mount, and proves the real hook
preserves the read-only reseal invariant. The source tree also ships product
integration snippets for APT/dpkg, pacman/libalpm, DNF 4, DNF5/libdnf5, and a
systemd image-seal unit, all pointing at stable hook names.
`hdn-recovery-action` is the recovery UI facade above the same typed backends.
Product recovery config maps stable action names to either brokered policy
rollback or a named system transaction, so recovery flows offer repair actions
without exposing `securityfs` or raw broker commands. QEMU proves unknown
recovery actions and unsafe recovery configs fail closed, and proves an
approved recovery policy rollback restores generation 0 through the broker and
an approved package repair action updates the product mount through the named
system transaction while preserving the read-only reseal invariant.
`hdn-recovery-describe` is the read-only recovery metadata facade. Recovery UI
asks for a named action and receives stable title/message/consequence/risk
fields from a root-owned manifest before it offers that action to a user. It
does not execute repair work. QEMU proves unknown recovery metadata actions
and unsafe metadata configs fail closed, and proves an approved
policy-rollback action emits the expected stable metadata.
`hdn-recovery-session` is the root-side session facade for products that want
the backend to enforce the complete recovery order. It obtains metadata through
`hdn-recovery-describe`, passes that metadata to a product confirmation or
authentication helper over stdin, and calls `hdn-recovery-action` only after
the helper exits successfully. The root-owned session config selects absolute
helper paths and does not invoke a shell. QEMU proves unknown actions, unsafe
session configs, failed confirmation, and missing graphical sessions stop
before repair work, and proves an approved package-repair session reaches the
named recovery action, updates the sealed product mount, and reseals it
read-only. `hdn-recovery-prompt` is the starter recovery confirmation frontend
for this contract: it validates root-owned recovery metadata from stdin,
displays a continue/cancel dialog through common desktop prompt helpers, and
fails closed when no graphical session is available.
`hdn-recovery-portal` is the product recovery UI entrypoint above
`hdn-recovery-session`. Product config maps branded recovery UI actions such
as `rollback-policy` and `repair-system` to approved recovery-session actions,
so recovery panels and rescue shells do not expose helper paths, broker
arguments, or securityfs operations. QEMU proves unknown recovery UI actions
and unsafe portal configs fail closed, and proves approved rollback and repair
portal actions reach recovery-session while preserving the policy rollback and
read-only reseal invariants.

Broker decisions become signed policy transactions consumed by the policy state manager and kernel interface.

## Policy Compiler

The policy compiler converts product policy to compact kernel policy.

Inputs:

- package database
- app identity database
- file integrity state
- signatures
- admin settings
- developer mode state
- driver trust database
- enterprise policy if present
- recovery policy

Outputs:

- profile table
- reusable role templates expanded by the compiler
- authority table
- UID/GID subject profile map
- object rule table
- transition table
- trust table
- audit table
- rollback metadata

Properties:

- deterministic
- versioned
- signed or MACed locally
- transactionally installed
- rollback capable
- testable offline

The kernel should reject malformed, downgraded, unsigned, or incompatible policy blobs.

The first implemented subject map is deliberately compact rather than a
gradm-style userspace policy language: signed `subject uid <id> <profile>` and
`subject gid <id> <profile>` records select an account profile before the
default profile for non-privileged exec and credential transitions. UID rules
match real, effective, saved, and filesystem UIDs. GID rules match real,
effective, saved, filesystem, and supplementary groups. Privileged exec still
enters the sealed privileged profile, so account subject rules cannot silently
weaken setuid/filecap handling.

Profile records also carry an optional umask floor. The floor is ORed with the
process umask in `current_umask()`, which means it reaches ordinary VFS and
filesystem creation paths while only making creation modes stricter. QEMU
validates that a subject-selected profile with a `077` floor creates regular
files as private `0600` files and directories as private `0700` directories even
after the process explicitly sets its own umask to `000`.

Signed resource-limit rules add profile-scoped ceilings without making every
ordinary resource write promptable. Text policy can declare
`resource PROFILE RLIMIT SOFT HARD`, where `RLIMIT` is a Linux resource name or
number and either limit can be `infinity`. Enforcement runs in the shared
`setrlimit(2)`/`prlimit64(2)` path against the target task's active HDN profile,
so a privileged helper cannot accidentally raise a restricted profile beyond the
sealed ceiling. QEMU validates `NOFILE` soft and hard ceiling denials and records
them with the `RESOURCE_PROFILE_LIMIT` reason.

The signed exec identity map supports both explicit `exec PROFILE ...`
transitions and `exec inherit ...` rules. Inheritance rules match executable
identity the same way as ordinary exec rules but preserve the caller's active
profile, optionally scoped with `parent PROFILE`. This covers profile-preserving
helper launches without making the runtime path resolve a userspace role graph.

The first implemented role layer is also deliberately compiler-side. Text
policy can define reusable `role NAME allow|audit|mem|response|feature ...`
templates, nest them with `role CHILD include PARENT...`, and attach them with
`use-role PROFILE NAME`. The compiler recursively expands parent roles into
child roles with missing-parent and cycle rejection, then writes the final grants
into sealed profile records before signing. This gives policy authors role reuse
and inheritance without making kernel hot paths resolve names or role graphs.

The first implemented object layer follows the same compact shape. Text policy
can declare `object PROFILE deny-write path PATH`,
`object PROFILE deny-read path PATH`, `object PROFILE deny-delete path PATH`,
`object PROFILE deny-create path PATH`, `object PROFILE deny-exec path PATH`,
`object PROFILE append-only path PATH`, `object PROFILE deny-link path PATH`,
`object PROFILE deny-link-target path PATH`,
`object PROFILE deny-attr path PATH`, `object PROFILE deny-chmod path PATH`,
`object PROFILE deny-chown path PATH`, `object PROFILE deny-utime path PATH`,
`object PROFILE deny-setid path PATH`,
`object PROFILE deny-xattr path PATH`,
`object PROFILE deny-setxattr path PATH`,
`object PROFILE deny-removexattr path PATH`,
`object PROFILE deny-creat path PATH`, `object PROFILE deny-mkdir path PATH`,
`object PROFILE deny-mknod path PATH`, `object PROFILE deny-symlink path PATH`,
`object PROFILE deny-unlink path PATH`, `object PROFILE deny-rmdir path PATH`,
	`object PROFILE deny-access path PATH`, `object PROFILE deny-stat path PATH`,
	`object PROFILE deny-list path PATH`, `object PROFILE deny-find path PATH`,
	`object PROFILE deny-ioctl path PATH`, `object PROFILE deny-lock path PATH`,
	`object PROFILE deny-watch path PATH`, `object PROFILE deny-receive path PATH`,
	`object PROFILE deny-fcntl path PATH`, `object PROFILE deny-chdir path PATH`,
	`object PROFILE deny-mount path PATH`,
	`object PROFILE deny-mount-source path PATH`,
	`object PROFILE deny-umount path PATH`,
	`object PROFILE deny-truncate path PATH`,
	`object PROFILE deny-rename path PATH`,
	`object PROFILE deny-rename-target path PATH`,
	`object PROFILE deny-unix-connect path PATH`,
	`object PROFILE deny-unix-bind path PATH`,
	`object PROFILE deny-unix-listen path PATH`,
	`object PROFILE deny-unix-accept path PATH`,
	`object PROFILE deny-unix-send path PATH`,
	`object PROFILE deny-unix-recv path PATH`, or recursive
	`object PROFILE OP tree DIRECTORY` rules, or equivalent
	`object PROFILE OP inode MAJOR MINOR INO` rules for the same object
	operations. Path and tree declarations are resolved to file
	or directory identity when the signed policy is staged, and VFS
	read/write/delete/create/creat/mkdir/mknod/symlink/unlink/rmdir/exec/link/link-target/attr/chmod/chown/utime/setid/xattr/setxattr/removexattr/access/stat/list/find/ioctl/lock/watch/receive/fcntl/chdir/mount/mount-source/umount/truncate/rename/rename-target/unix-connect/unix-bind/unix-listen/unix-accept/unix-send/unix-recv paths check compiled identity under RCU.
Tree declarations must resolve to directories and match that directory plus
descendants by dentry ancestry. This
slice covers recursive denial rules, recursive split create/delete operation
rules, recursive append-only rules, recursive descriptor-control,
operation-tree, target-tree, and preopened-descriptor unmatched checks, fd-receive, mount topology with unmatched-target and source checks, split metadata/xattr, and filesystem-socket IPC operation rules, regular-file write opens, `write(2)`, `writev(2)`,
pipe-to-file `splice(2)`, `copy_file_range(2)` destination writes,
truncate/ftruncate, and fallocate; append-only files allow
`O_APPEND`/`RWF_APPEND` writes while denying non-append writes through
already-open descriptors, pipe-to-file `splice(2)`, `copy_file_range(2)`
destination writes, exported iterator writes, legacy AIO and io_uring writes
that do not carry append intent, truncate/ftruncate, and fallocate. It also covers
	regular-file read opens, read paths through `rw_verify_area()`, readable
	file `mmap(2)`, and readable `mprotect(2)` upgrades, including already-open
	descriptors after policy commit, regular-file
unlink/rename/replacement, split `unlink(2)` and `rmdir(2)` gates that fall
back to aggregate delete policy, and parent-directory create denial for
regular-file create, `mkdir(2)`, `mknod(2)`, `symlink(2)`, `link(2)`, tmpfile
creation, and rename into a protected directory. Split `creat`, `mkdir`, `mknod`, and
`symlink` object rules gate their named creation operations before falling back
to aggregate create policy. It covers `execve(2)` and file-backed executable
`mmap(2)`/`mprotect(2)` transitions for protected executable objects, plus
hardlink attempts from protected regular-file sources and incoming hardlinks by
target directory identity. It also covers aggregate
mode, ownership, size, explicit timestamp changes through the common setattr
path, VFS file-attribute flag changes through the common fileattr path, and
extended attribute set/remove operations through the common VFS xattr paths,
plus split `chmod(2)`, `chown(2)`, utime-style timestamp mutation,
setid-bit introduction through mode changes or creation requests,
`setxattr(2)`, and `removexattr(2)` object rules for exact policy gates. It
also covers explicit `access(2)`/`faccessat(2)` probes through
`deny-access`, and makes `R_OK`/`W_OK`/`X_OK` probes observe regular-file
deny-read, deny-write, and deny-exec policy. Metadata discovery through the
common VFS getattr path is covered by `deny-stat`, including path-based stat
calls, `fstat(2)` on descriptors opened before policy commit, and VFS
file-attribute reads such as `FS_IOC_GETFLAGS`. Directory name discovery
through the common VFS `iterate_dir()` path is covered by
`deny-list`, including `readdir(3)`/`getdents64(2)` and directory descriptors
opened before policy commit. Name-discovery opens are covered by `deny-find`
for regular non-directory `open(2)`, `open(2)` with `O_PATH`, and
`name_to_handle_at(2)`, returning `ENOENT` while recording an `OBJECT_FIND`
denial event. Regular open checks run after more specific read/write denials,
so combined tree rules still report their data-access denial; directory
enumeration uses deny-find per entry rather than denying the containing
directory open. Descriptor passing and descriptor-control surfaces are covered
through `security_file_receive()` and `security_file_fcntl()`: `deny-receive`
blocks received protected file descriptors, and `deny-fcntl` blocks
mutating/control fcntl commands plus
	ioctl aliases for close-on-exec, nonblocking, and async flag changes while
	leaving status queries usable. `deny-lock` covers BSD `flock(2)`, POSIX/OFD
	`fcntl(2)` lock acquisition, and file lease acquisition through `F_SETLEASE`
	while leaving unlock operations usable. `deny-chdir` covers `chdir(2)` and
	`fchdir(2)`, `deny-mount` covers mount-tree attachment through
	`mount(2)` and the `move_mount(2)` destination path,
	`deny-mount-source` covers `move_mount(2)` and legacy `mount(2)` `MS_MOVE`
	source paths, and `deny-umount` covers validated `umount(2)`/`umount2(2)`
	detach attempts.
	`deny-truncate` separately covers path truncation, descriptor truncation,
	`O_TRUNC` opens, and `fallocate(2)` extent mutation without blocking
	ordinary writes. `deny-rename` covers source-object rename attempts and
	both source objects in `RENAME_EXCHANGE`. `deny-rename-target` covers
	incoming rename attempts by destination directory identity without
	blocking ordinary creates in that directory. `deny-unix-connect` covers
	filesystem-backed AF_UNIX pathname socket connect attempts, and
	`deny-unix-bind` covers filesystem-backed AF_UNIX pathname socket bind
	attempts by parent directory identity before the socket node is created.
	`deny-unix-listen` and `deny-unix-accept` cover filesystem-backed
	AF_UNIX listener operations by bound socket identity. `deny-unix-send`
	covers pathname and connected AF_UNIX datagram sends by destination
	socket identity, and `deny-unix-recv` covers datagram receives by bound
	socket identity.
	It is still a compact
	object-policy base, not a full RBAC object language.

## Sealing Model

The sealing model protects kernel and policy state from runtime mutation.

Phases:

```text
HDN_PHASE_BOOT
HDN_PHASE_INIT
HDN_PHASE_POLICY_LOAD
HDN_PHASE_RUNTIME
HDN_PHASE_RECOVERY
```

Example object declarations:

```text
kernel text: mutable until init text finalized, then executable read-only
module text: mutable during relocation, then executable read-only
module rodata: mutable during relocation, then read-only
policy table: mutable during policy transaction, then read-only/RCU-published
authority table: mutable during policy transaction, then read-only/RCU-published
security hooks: mutable during LSM init, then read-only
```

Mutation outside the allowed phase is a kernel security event and may trigger
exploit response policy. The first implemented invariant reporter hooks the
x86 supervisor write-protection fault path before exception-table fixup and
records sealed HDN mitigation/policy page writes as `HDN_TRANS_SEALED_DATA`
with `HDN_REASON_SEALED_DATA_WRITE`.

## Compiler and Language Hardening

The design should avoid depending on a private compiler dialect where possible.

Preferred order:

1. Upstream compiler features.
2. Upstream kernel annotations and hardening options.
3. Objtool and build-time verification.
4. Small original compiler passes only where necessary.
5. Rust components where they remove real unsafe surface.

Hardening goals:

- indirect call integrity
- return address integrity where available
- strict function pointer typing
- checked integer size transitions
- hardened refcount semantics
- stack initialization and clearing
- heap initialization and clearing
- structure layout randomization where ABI-safe
- immutable-after-init data
- detection of unexpected mutable global dispatch tables

The source language story is practical:

- Existing Linux remains C and assembly.
- New policy tooling and userspace services should be Rust.
- New kernel code may use Rust where supported and where it reduces memory safety risk without fighting subsystem reality.

## Filesystem and Object Identity

Path names are unstable. Enforcement should prefer stable identities.

Identity sources:

- inode and mount identity
- package database identity
- fs-verity digest
- signature
- measured boot state
- file capability state
- interpreter chain
- app bundle manifest

Path-based policy can exist as an input language, but kernel hot paths should use compiled identities and labels.

Important rule:

> The policy compiler may understand paths. The kernel enforcement path should consume identities.

## Namespaces, Containers, and Chroot

Containers and chroot-like environments are not treated as security boundaries unless assigned a namespace profile.

Default policy:

- user namespace creation is restricted
- mount namespace creation is profile-controlled
- privileged namespace combinations require authority
- procfs/sysfs sensitive visibility is namespace-profile-aware
- container runtime profiles are explicit
- nested container behavior is deliberate, not accidental

The kernel should enforce namespace profile inheritance and downgrade rules.

## Exploit Response

The system should distinguish:

- normal denial
- suspicious denial
- probable exploit attempt
- confirmed invariant violation

Responses:

- audit only
- terminate process
- terminate process tree
- revoke profile grants
- temporarily restrict account
- require re-authentication
- force reboot into recovery for kernel invariant violation

Exploit response must avoid punishing normal users for app bugs where possible. Kernel invariant violations are different: they imply possible kernel compromise and justify stronger action.

HDN implements the first kernel-invariant lockout slice with
`SECURITY_HARDENING_KERNEL_LOCKOUT`. On x86, a kernel-mode page-fault oops
reports a kernel-surface fault. If the current uid is root, the system panics.
For a non-root uid, HDN records `KERNEL_LOCKOUT`, bans that uid until reboot,
kills existing tasks for that uid, and denies later fork, exec, or
credential-entry attempts for the banned uid. A policy-admin-only
`kernel_lockout_probe` securityfs file lets the harness prove the response path
without intentionally crashing the VM.

## Recovery Model

Recovery is a product feature, not an afterthought.

Required recovery paths:

- boot previous known-good kernel
- boot previous known-good policy
- disable recently approved driver
- disable developer mode
- repair broken app policy
- export security logs
- restore default hardening profile

Recovery UI should explain product actions:

```text
The last driver approval prevented startup.
Disable that driver and continue.
```

Not:

```text
Drop to root shell and edit policy.
```

## Kernel Interface

The kernel interface should be small and boring.

Candidate interfaces:

- `securityfs` for read-only state and diagnostics.
- Netlink or a dedicated misc device for policy transactions.
- Tracepoints or ring buffer for structured audit events.
- No human-edited kernel policy language.

Operations:

```text
HDN_LOAD_POLICY
HDN_COMMIT_POLICY
HDN_ROLLBACK_POLICY
HDN_QUERY_PROFILE
HDN_QUERY_AUTHORITY
HDN_SUBSCRIBE_EVENTS
HDN_SET_RECOVERY_BOOT
```

Only the policy state manager can load policy. The desktop authorization broker never writes kernel policy directly.

## Patch Surface Strategy

The kernel patch should be organized around contract points, not feature sprawl.

New implementation lives primarily under:

```text
security/hardening/
include/linux/hardening.h
include/uapi/linux/hardening.h
```

Core subsystem edits are limited to narrow calls into that layer.

Expected call sites:

```text
fs/exec.c:
  establish executable identity and attach an exec profile

kernel/cred.c:
  mediate credential transitions, UID/GID subject profile selection, profile
  inheritance, and multithreaded setxid propagation

kernel/exit.c:
  record crash signals for privileged-exec brute-force throttling and
  same-binary daemon fork throttling

mm/mmap.c and mm/mprotect paths:
  rewrite or deny executable-memory transitions

kernel/module/:
  authorize module admission and seal module memory
  route one-argument request_module calls as exact names
  provide bounded HDN context to authorized modprobe helpers
  report upstream module-load lockout availability

drivers/base/firmware_loader/:
  authorize firmware admission

kernel/bpf/:
  authorize BPF program load, map/BTF/link/token creation, attach/update,
  fd-by-id acquisition, ID enumeration, metadata queries, map operations,
  pin/get operations, test-run, iter, stats, token, and struct-ops operations
  require disclosure authority before the BPF kallsyms lookup helper resolves
  user-provided symbol names
  require disclosure authority before the BPF verifier resolves pseudo-BTF
  kernel symbol references to concrete addresses
  require disclosure authority before BPF kfunc calls, BPF tracing attach
  targets, or BTF kptr destructors resolve kernel BTF names to concrete
  addresses
  require disclosure authority before sysfs exposes built-in or module BTF blobs
  through read or mmap paths

net/core/net-procfs.c:
  redact packet handler function symbols in /proc/net/ptype without disclosure
  authority

kernel/time/timer_list.c:
  redact timer and clock-event callback symbols in /proc/timer_list without
  disclosure authority

kernel/events/:
  authorize perf access

arch/x86/kernel/vm86_32.c:
  authorize VM86 entry and VM86 IRQ helper commands on x86-32 kernels

kernel/ptrace.c:
  authorize debugging checks

mm/memory.c:
  prevent forced remote reads from bypassing execute-only VMAs

mm/process_vm_access.c and mm/madvise.c:
  authorize explicit remote process memory operations

mm/migrate.c and mm/mempolicy.c:
  authorize explicit remote process page migration and placement operations

kernel/pid.c:
  authorize explicit remote process file-descriptor extraction

kernel/user_namespace.c:
  authorize user namespace creation

fs/proc/:
  gate process visibility and kernel disclosure

fs/debugfs/:
  gate debugfs visibility and mutation

fs/tracefs/:
  gate tracefs visibility and mutation
  gate kernel symbol list and symbol-resolution frontends through disclosure
  authority
  redact central trace/probe symbol formatting without disclosure authority
  suppress BTF-backed function-argument decoding without disclosure authority
  require disclosure authority before BPF kprobe-multi resolves
  user-provided kernel symbol names

lib/vsprintf.c:
  redact `%pS`, `%ps`, and `%pB` symbolic pointer formatting without
  disclosure authority

kernel/kallsyms.c:
  redact `sprint_symbol*()` formatting without disclosure authority

mm/vmalloc.c:
  redact `/proc/vmallocinfo` caller symbols without disclosure authority

mm/slub.c:
  redact slab constructor sysfs symbols and SLUB debugfs allocation/free trace
  symbols without disclosure authority

kernel/kprobes.c:
  redact kprobe debugfs symbol names without disclosure authority

kernel/fail_function.c:
  require disclosure authority before function-error-injection resolves
  user-provided kernel symbol names
  use pseudonymous debugfs entry directories and redact symbol listings without
  disclosure authority

lib/error-inject.c:
  redact the global function-error-injection injectable-symbol catalog without
  disclosure authority

kernel/kcsan/debugfs.c:
  require disclosure authority before KCSAN debugfs report filters resolve
  user-provided kernel symbol names
  redact KCSAN report-filter symbol listings without disclosure authority

kernel/locking/lockdep.c:
  redact lockdep key-name symbol reporting without disclosure authority

fs/sysfs/ and driver core:
  gate owner-only visibility, sensitive kernel metadata visibility, and risky
  mutation surfaces

kernel/kexec*:
  authorize kexec image load
  report upstream kexec-load lockout availability

io_uring/:
  gate SQPOLL setup and registration operations that meaningfully expand attack
  surface
  make the global io_uring disable sysctl monotonic once tightened

ipc/:
  harden overly permissive System V IPC and POSIX mqueue access

drivers/tty/:
  gate terminal input-injection ioctls

fs/namespace.c, fs/fsopen.c, fs/super.c:
  gate FUSE mount creation, read-only mount/superblock relaxation, and
  profile-enforced denial of new writable mounts with profile-scoped updater
  bypasses

fs/namei.c, fs/open.c, fs/read_write.c, fs/attr.c, fs/xattr.c, fs/stat.c, fs/readdir.c, fs/fhandle.c, fs/namespace.c, net/unix/af_unix.c, security/security.c:
  enforce signed object read/write/delete/create/creat/mkdir/mknod/symlink/unlink/rmdir/exec/link/link-target/attr/chmod/chown/utime/setid/xattr/setxattr/removexattr/access/stat/list/find/ioctl/lock/watch/receive/fcntl/chdir/mount/mount-source/umount/truncate/rename/rename-target/unix-connect/unix-bind/unix-listen/unix-accept/unix-send/unix-recv
  denial, append-only, recursive split-operation tree, recursive descriptor,
  operation-tree, target-tree, and preopened-descriptor unmatched checks, fd-receive, mount topology with unmatched-target and source checks, split metadata/xattr, and filesystem-socket IPC operation tree, and recursive
  append-only tree rules by compiled identity

tools/hardening/hdn-rofs-apply:
  make product-selected already-mounted paths read-only after policy commit
  without granting the helper authority to make them writable again; list files
  must be root-owned, non-writable by group/other, regular files, and not
  symlinks; entries may be legacy bare required paths, explicit
  `required PATH`, or `optional PATH` entries that are skipped unless the path
  is currently a mounted filesystem

tools/hardening/hdn-rofs-transaction:
  temporarily relax a product-selected read-only mount for an updater command,
  then reseal the mount read-only before returning

tools/hardening/hdn-image-seal:
  map installer, first-boot, and image-updater seal names from a root-owned
  product config to ordered brokered policy-commit and ROFS apply steps

tools/hardening/hdn-system-transaction:
  map package-manager/image-updater operation names from a root-owned product
  config to brokered ROFS transactions, so package tools do not pass raw
  mountpoint or worker paths

tools/hardening/hdn-package-hook:
  map package-manager hook names from a root-owned product config to named
  system transactions or image seals, so package scripts and image builders do
  not know backend helper paths

tools/hardening/package-manager-hooks/:
  provide installable APT/dpkg, pacman/libalpm, DNF 4, DNF5/libdnf5, and
  systemd image-seal integration snippets that call hdn-package-hook stable
  actions

tools/hardening/Makefile install:
  stages helper binaries, root-owned product config templates, and shipped
  package-manager/systemd hook snippets into the distro filesystem layout with
  DESTDIR and directory-variable overrides for packaging

tools/hardening/hdn-recovery-action:
  map recovery UI action names from a root-owned product config to brokered
  policy rollback or named system transactions, so repair flows do not expose
  raw broker/securityfs operations

tools/hardening/hdn-recovery-describe:
  map recovery UI action names from a root-owned product metadata manifest to
  stable title/message/consequence/risk output, so recovery text is
  product-owned and not inferred from raw repair commands

tools/hardening/hdn-recovery-session:
  enforce the root-side recovery sequence of describe, confirm, then act for
  named recovery actions, so a recovery frontend can wrap one backend command
  without exposing raw broker/securityfs operations

tools/hardening/hdn-recovery-portal:
  map branded recovery UI actions from a root-owned product config to
  recovery-session actions, so recovery panels and rescue shells call a stable
  product contract instead of helper paths or raw action names

tools/hardening/hdn-recovery-prompt:
  read root-owned recovery metadata from stdin, display a dependency-light
  graphical continue/cancel prompt through the desktop session, and fail
  closed without a display or valid metadata

tools/hardening/hdn-prompt-dispatch:
  map desktop prompt action names from a root-owned product config to
  token-backed broker intents after authentication, so prompt daemons do not
  construct raw broker command lines

tools/hardening/hdn-prompt-describe:
  map desktop prompt action names from a root-owned product metadata manifest
  to stable title/message/consequence/risk output before authentication, so
  prompt UI text is product-owned and not inferred from raw broker arguments

tools/hardening/hdn-prompt-session:
  enforce the root-side prompt sequence of describe, authenticate, then
  dispatch for named product actions, so a desktop frontend can wrap one
  backend command without seeing token or broker arguments

tools/hardening/hdn-prompt-portal:
  map branded desktop action names from a root-owned product manifest to the
  prompt-session backend, giving shells and settings panels one stable command
  while keeping session helper paths, tokens, and broker arguments hidden

tools/hardening/hdn-auth-prompt:
  read root-owned prompt metadata from stdin, display a dependency-light
  graphical allow/cancel prompt through the desktop session, and fail closed
  without a display or valid metadata

tools/hardening/hdn-event-decode:
  translate raw securityfs hardening event records into stable UAPI names for
  product UI, log export, and smoke harness assertions, including common packed
  object payload details for exec arguments, signals, resources, time changes,
  USB, coredumps, and sockets

tools/hardening/hdn-policy-learn:
  translate denied hardening events into a reviewable HDN-native policy
  fragment for developer-mode, settings UI, or support workflows, while leaving
  W+X, untrusted code identity, policy-admin, credential, and broad bypass
  decisions as comments that require human/product review

tools/hardening/hdn-policy-merge:
  merge reviewed learner `allow` and `mem` suggestions into a candidate text
  policy without editing the base in place, refusing unknown profiles and
  duplicate-only suggestions before the candidate reaches compile/sign/commit

tools/hardening/hdn-policy-workflow:
  run root-owned named policy review workflows above `hdn-policy-learn` and
  `hdn-policy-merge`, rejecting unknown workflows, unsafe configs, unsafe
  paths, and input/output path reuse before a UI or support tool can generate a
  fragment or candidate policy

tools/hardening/hdn-admin-broker:
  accept typed privileged product intents for prompt daemons, dispatch the ROFS
  helpers directly only after a root-owned product allowlist approves the
  requested mount/worker/list, and stage signed policy commit or rollback
  operations from product-approved policy locations; missing or writable
  allowlists fail closed

kernel/time/:
  gate wall-clock, timezone, and mutable adjtimex changes, and record
  process CPU-time and realtime-runtime resource pressure

kernel/sys.c:
  gate hard resource-limit raises

fs/file.c, fs/read_write.c, fs/attr.c, fs/locks.c:
  record low-cost resource pressure telemetry for fd, file-size, and file-lock
  conflict paths

fs/coredump.c:
  record core-size resource pressure when `RLIMIT_CORE` suppresses coredumps

kernel/fork.c, kernel/signal.c, kernel/sched/syscalls.c, mm/mmap.c,
mm/vma.c, mm/mlock.c, ipc/mqueue.c:
  record process-count, VM/data/stack, memlock, and POSIX mqueue resource
  pressure, plus pending-signal, nice-priority, and RT-priority pressure

net/ipv4, net/ipv6:
  suppress remote closed-port TCP/UDP/protocol responses, keep loopback
  diagnostics, bound LAST_ACK retries, and remove TCP crossed-SYN simultaneous
  open

arch/*:
  implement page-table, sealing, CFI, entry, and low-level memory invariants
```

Patch rules:

- Core subsystems pass request objects to hardening code.
- Core subsystems do not parse product policy.
- Core subsystems do not format user-facing messages.
- Hot-path hooks avoid string parsing, path walks, dynamic allocation, and policy compilation.
- Every authority gate has a stable event ID.
- Every profile exception has a reason code.
- Every new gate has a harness test.
- Every denial has enough structured data for diagnosis.
- Every rewrite is visible through audit when audit is enabled.
- Every emergency bypass is explicit, logged, and scoped.

Good patch shape:

```c
decision = hdn_mmap_rewrite(&req);
if (decision.denied)
    return decision.errno;

prot = req.prot;
flags = req.flags;
```

Bad patch shape:

```c
if (desktop_mode && special_case_browser && user_clicked_button)
    allow_weird_mapping();
```

The first shape creates a stable kernel contract. The second shape bakes product behavior into memory-management code.

## Compatibility Strategy

Compatibility is handled through profiles, not global weakening.

Examples:

- Browser JIT gets a JIT profile.
- Packaged runtimes that cannot be profiled cleanly may carry a narrow HDN ELF memory note instead of weakening global memory policy.
- Game compatibility gets specific memory and anti-cheat allowances.
- Virtualization gets explicit device, module, and namespace authorities.
- Developer shells get broader ptrace/perf/userns grants than normal apps.
- Legacy enterprise software can get a legacy profile with visible risk labeling.

The user should not be asked to understand the mechanism. They approve product-level intents.

## Test Oracles

The harness should test outcomes, not implementation resemblance.

Core oracle groups:

### Memory Execution

- anonymous RWX mapping denied
- file-backed RWX mapping denied
- unauthorized `mprotect(PROT_EXEC)` denied
- authorized JIT path works
- trusted HDN ELF memory note allows only its scoped memory compatibility exceptions
- fixed executable mapping restrictions hold
- compatibility exceptions are profile-scoped
- page-table checking is enforced on architectures that support upstream
  `PAGE_TABLE_CHECK`
- `vm.mmap_min_addr` has a locked low-address floor and unprivileged fixed
  mappings below that floor are denied

### Attack Surface

- unprivileged BPF denied
- restricted profiles denied BPF map creation and metadata enumeration under
  `BPF_LOAD`, with denials audited
- unauthorized perf kernel access denied
- unprivileged userfaultfd kernel-fault handling unavailable or locked at
  user-mode-only syscall semantics
- ptrace constrained by profile
- direct native and compat ptrace attach/seize attempts emit structured ptrace
  audit events after the profile gate, preserving success or later upstream
  kernel denial
- multithreaded root-to-nonroot setxid drops propagate to sibling threads
  through fixed per-task work, avoiding an arch-specific delayed-cred flag
- user namespace policy enforced
- debugfs and tracefs hidden or constrained
- trace/probe symbol listing, symbol lookup, and symbolic pointer formatting
  denied or redacted without `PROC_DISCLOSE`
- BTF-backed function-argument decoding in ftrace output suppressed without
  `PROC_DISCLOSE`
- `/proc/vmallocinfo`, slab constructor sysfs, and SLUB debugfs trace symbols
  redacted without `PROC_DISCLOSE`
- `/proc/net/ptype` packet-handler function symbols redacted without
  `PROC_DISCLOSE`
- `/proc/timer_list` timer and clock-event callback symbols redacted without
  `PROC_DISCLOSE`
- function-error-injection debugfs entry names pseudonymized and its symbol
  resolution/listing/injectable catalog denied or redacted without
  `PROC_DISCLOSE`
- KCSAN debugfs symbol resolution/listing denied or redacted without
  `PROC_DISCLOSE`
- BPF kallsyms helper, pseudo-BTF kernel-symbol resolution, BPF kfunc
  address resolution, BPF tracing target address resolution, BTF kptr
  destructor address resolution, BTF sysfs blob read/mmap, and kprobe-multi
  symbol-name resolution denied without `PROC_DISCLOSE`, even when the
  profile has BPF authority
- procfs task visibility constrained and kernel disclosure redacted
- procfs memory-map and stat address disclosure redacted without
  `PROC_DISCLOSE`, while self reads and authorized admin reads remain usable
- cross-process `/proc/<pid>/pagemap`, `PROCMAP_QUERY`, and global
  `/proc/kpage*` page-monitoring metadata denied without `PROC_DISCLOSE`,
  while `/proc/self/pagemap` remains usable
- `/proc/ioports` and `/proc/iomem` address ranges redacted without
  `PROC_DISCLOSE`, while resource names remain visible for compatibility
- owner-only sysfs attributes and sensitive world-readable sysfs metadata such
  as `/sys/kernel/vmcoreinfo`, `/sys/kernel/notes`, and
  `/sys/kernel/boot_params/data` are denied and hidden without `SYSFS_READ`,
  while ordinary device-discovery sysfs entries remain visible
- setuid privileged exec rejects oversized argv/env stacks and caps inherited
  stack rlimits before mmap layout selection
- kernel logs redacted
- unsigned module load denied
- implicit module autoload denied without profile authority
- exact-name request_module dispatch reported in sealed status
- modprobe helper receives bounded autoload context
- modprobe helper path writes denied without module-autoload authority
- unsafe modprobe helper path writes denied even with module-autoload authority
- one-way module and kexec load lockouts reported in sealed status
- same-binary daemon worker crashes temporarily delay later daemon forks
- successful exec operations emit structured exec audit events
- successful exec operations emit privacy-preserving `EXEC_ARGS` argument and
  environment count telemetry
- successful exec operations from chrooted tasks carry a structured chroot
  event flag
- contained-chroot denials emit operation-specific reason codes for chmod,
  mknod, mount, file-handle opens, sysctl writes, shmat, priority, rename,
  abstract UNIX sockets, capability use, and outside-task targeting
- successful chdir/fchdir operations emit structured chdir audit events
- successful mount administration operations emit structured mount audit events
- severe fault-style signals emit structured signal audit events
- cross-profile user-originated signal sends are denied without `SIGNAL`
  authority while direct-child job control remains usable
- cross-profile `process_vm_readv`, `process_vm_writev`,
  `process_madvise`, and `process_mrelease` operations are denied without
  `PROCESS_MEMORY` authority while same-profile cooperating processes remain
  usable
- cross-profile `move_pages` and `migrate_pages` operations are denied
  without `MEMORY_MIGRATE` authority while same-profile page-location queries
  remain usable
- cross-profile `pidfd_getfd` operations are denied without `PROCESS_FD`
  authority while same-profile pidfd descriptor sharing remains usable
- sibling or unrelated `pidfd_open` task-handle creation for other-user tasks
  is denied without `PROC_TASK_VIEW`, `PROC_DISCLOSE`, or the configured
  proc task-view group, while direct-child pidfd supervision remains usable
- public `/proc/<pid>`, `/proc/<pid>/task`, and `/proc/<pid>/task/<tid>`
  directories are owner-and-configured-task-view-group traversable instead of
  world-traversable when the global proc task-view group is configured
- `PIDFD_GET_INFO` metadata reads on inherited or IPC-received pidfds are
  denied for sibling or unrelated other-user tasks without `PROC_TASK_VIEW`
  or `PROC_DISCLOSE`, unless the caller is in the configured proc task-view
  group
- `/proc/self/fdinfo/<pidfd>` redacts received pidfd target PIDs for sibling
  or unrelated other-user tasks without `PROC_TASK_VIEW` or `PROC_DISCLOSE`,
  unless the caller is in the configured proc task-view group
- pidfd-backed `setns()` namespace harvesting is denied for sibling or
  unrelated other-user tasks without `PROC_TASK_VIEW` or `PROC_DISCLOSE`, even
  when the caller has namespace administration authority, unless the caller is
  in the configured proc task-view group
- pidfd namespace fd ioctls such as `PIDFD_GET_UTS_NAMESPACE` are denied for
  sibling or unrelated other-user tasks without `PROC_TASK_VIEW` or
  `PROC_DISCLOSE`, even when the caller has namespace administration
  authority, unless the caller is in the configured proc task-view group
- failed fork attempts caused by process-count or memory pressure emit
  structured fork-failure audit events
- profiles can reject new writable mounts while allowing read-only mounts
- a scoped updater/recovery exec profile with `AUTH_ROFS_RELAX` can still
  perform the product-approved writable mount operation
- the product ROFS apply helper can make an already-mounted path read-only
  under a narrow `AUTH_MOUNT_ADMIN` profile that lacks `AUTH_ROFS_RELAX`, and
  writes through that mount fail afterward
- the ROFS apply helper accepts root-owned path lists with `required` and
  `optional` entries, skips absent or non-mounted optional paths, and still
  seals required mounted paths
- the admin broker denies unapproved read-only mount lists and can broker an
  approved `rofs-apply -f` list into the narrow apply helper only when the list
  itself is a safe root-owned file, leaving listed mounts read-only
- the product ROFS transaction helper can temporarily relax that sealed mount
  under `AUTH_ROFS_RELAX`, run the updater command, reseal the mount read-only,
  and leave later writes failing with `EROFS`
- the admin broker can accept a typed ROFS transaction intent, transition
  through the broker profile into the ROFS transaction helper, update the sealed
  mount, and leave later writes failing with `EROFS`
- the admin broker rejects an unapproved ROFS worker before it can modify the
  sealed product mount
- the admin broker fails closed when its product allowlist is missing or
  writable
- the admin broker can commit a signed policy from a product-approved policy
  directory and roll it back through the typed rollback intent
- the admin broker denies signed policy blobs outside approved policy
  directories without staging them or changing active generation
- the admin broker can require a desktop-prompt approval token, rejects missing,
  unsafe, wrong-intent, and expired tokens, accepts a valid token for the typed
  intent, consumes the token for real dispatch, and rejects replay
- the approval-token issuer rejects unknown intents and creates broker-valid
  short-lived tokens for known typed intents
- the prompt metadata helper rejects unknown prompt actions, rejects unsafe
  prompt metadata configs, and reports stable title/message/consequence/risk
  fields for an approved action without dispatching privileged work
- the prompt session helper rejects unknown prompt actions, rejects unsafe
  session configs, rejects failed authentication before dispatch, and runs an
  approved prompt action only after metadata handoff and authenticator success
- the prompt portal helper rejects unknown desktop actions, rejects unsafe
  portal configs, and maps an approved desktop action to prompt-session without
  exposing token, broker, or helper command lines
- the desktop-action helper rejects unknown UI verbs, rejects unsafe configs,
  and maps an approved UI verb to prompt-portal without exposing lower helper
  paths
- the desktop-daemon helper rejects unknown UI verbs, rejects unsafe configs,
  and runs an approved stdio UI action through desktop-action
- the control-center helper reports product status through hdn-status, rejects
  unknown UI actions, runs an approved UI action through hdn-desktop-daemon,
  reports product status through stdio, rejects unknown UI actions through
  stdio, runs an approved UI action through stdio, rejects non-commit policy
  dry-runs through stdio, and runs an approved policy workflow plus
  signed-commit preflight through hdn-policy-daemon
- the image seal helper rejects unknown seal names, rejects unsafe image seal
  configs, dry-runs an approved brokered read-only mount list without changing
  mount state, and applies that list while leaving the sealed mount read-only
- the system transaction helper rejects unknown package/update operation names,
  rejects unsafe transaction configs, dry-runs approved named transactions
  without changing the sealed mount, and runs them through the broker while
  preserving the read-only reseal invariant
- the package hook helper rejects unknown package-manager hook names, rejects
  unsafe hook configs, dry-runs approved named hooks without changing the
  sealed mount, and runs approved named hooks through the selected transaction
  or image-seal backend
- package-manager hook snippets for APT/dpkg, pacman/libalpm, DNF 4,
  DNF5/libdnf5, and the image-seal systemd unit invoke the stable
  hdn-package-hook actions
- the recovery action helper rejects unknown recovery action names, rejects
  unsafe recovery configs, runs approved policy rollback through the broker,
  and runs approved repair actions through named system transactions
- the recovery metadata helper rejects unknown recovery action names, rejects
  unsafe metadata configs, and reports stable title/message/consequence/risk
  fields for an approved action without dispatching repair work
- the recovery session helper rejects unknown recovery action names, rejects
  unsafe session configs, rejects failed confirmation before action dispatch,
  and runs an approved package repair action only after metadata handoff and
  confirmation success
- the recovery portal helper rejects unknown recovery UI action names, rejects
  unsafe portal configs, and maps approved recovery UI actions to
  recovery-session without exposing broker, securityfs, or helper command lines
- the prompt dispatch helper rejects unknown post-auth action names, rejects
  unsafe prompt configs, and runs an approved named package-update action
  through fresh approval-token issuance and the strict token-required broker
- the event decoder maps raw hardening event records to stable UAPI names,
  identifies a denied W+X event by decoded reason/action, and names common
  packed object details for exec arguments, signals, resources, time changes,
  USB, coredumps, and sockets
- the status helper maps raw hardening status to product-facing `key=value`
  state, reports policy readiness and mitigation totals, and decodes the latest
  audit-flood action/authority/transition/reason IDs to UAPI names; the
  control-center status facade covers the settings-shell entry point above it
- explicit denied W+X `mmap()` and `mprotect()` attempts also emit a dedicated
  `RWXMAP_DENIED` audit reason for grsec-class RWX-map telemetry without
  changing the existing `USER_WX_MAPPING` enforcement event
- executable `PT_GNU_STACK` ELF files mapped executable at file offset zero
  emit a named `EXEC_STACK_ELF` allow-audit event, covering another
  grsec-class RWX-map logging case without blocking legacy binaries by default
- native `ET_DYN` ELF files with `DT_TEXTREL` or `DF_TEXTREL` dynamic-section
  markings emit named `TEXTREL_MPROTECT` audit events on RX-to-RW or RW-to-RX
  mprotect transitions, covering the remaining grsec-class textrel RWX-map
  logging signal without changing HDN's mprotect enforcement decisions
- `vm.memfd_noexec` starts at enforced noexec mode, cannot be lowered below
  that floor, and explicit `MFD_EXEC` memfd creation is rejected
- `kernel.dmesg_restrict` starts at the restricted value and cannot be lowered
  below that floor while the exploit-mitigation baseline is enabled
- `/dev/kmsg` writes require the separate kernel-log write authority, allowing
  logging services without granting kernel-log read disclosure
- `kernel.yama.ptrace_scope` starts at relational mode and cannot be lowered
  below that floor while the exploit-mitigation baseline is enabled
- `fs.suid_dumpable` starts disabled and cannot be raised while the
  exploit-mitigation baseline is enabled
- `vm.mmap_min_addr` starts at or above the HDN 64 KiB floor and cannot be
  lowered below that floor while the exploit-mitigation baseline is enabled
- `vm.unprivileged_userfaultfd` cannot be raised when `CONFIG_USERFAULTFD` is
  enabled; when that syscall is not built, the same attack surface is absent
- upstream `kernel.modules_disabled` and `kernel.kexec_load_disabled` are
  reported as available one-way code-loading lockouts when built
- one-argument `request_module()` exact-name dispatch is reported in sealed
  status when module autoload support is built
- bounded modprobe helper context is reported in sealed status and proved with
  an authorized autoload fixture
- `dev.tty.legacy_tiocsti` and `dev.tty.ldisc_autoload` are forced off while
  TTY injection hardening is enabled and cannot be re-enabled through sysctl
- failed fork attempts emit a named `FORK_FAILED` audit reason and preserve the
  errno that caused process creation to fail
- upstream protected symlink, hardlink, FIFO, and regular-file sticky-directory
  sysctls are locked at hardened floors, and their denials emit named
  `FS_PROTECTION` audit events without changing the upstream access-control
  decision
- non-root symlink owner mismatches against the final resolved target are
  denied outside the upstream sticky-directory-only case and reported with a
  named `SYMLINK_OWNER_MISMATCH` filesystem-protection reason in QEMU
- ptrace attach/seize attempts that pass HDN profile authorization emit named
  `PTRACE` audit events for successful attaches and later upstream denials
- multithreaded root-to-nobody uid/gid drops are visible from sibling threads
  in QEMU, proving consistent setxid propagation without broad userspace help
- contained chroot proc-sysctl writes are denied and reported with a named
  `CHROOT_SYSCTL` reason in QEMU
- successful time changes emit structured time-change audit events
- successful resource-limit writes emit structured resource-limit audit events
- signed profile resource ceilings deny soft and hard limit raises above policy
- `RLIMIT_NOFILE`, `RLIMIT_FSIZE`, `RLIMIT_CORE`, `RLIMIT_AS`,
  `RLIMIT_DATA`, `RLIMIT_STACK`, `RLIMIT_NPROC`, `RLIMIT_MEMLOCK`,
  `RLIMIT_MSGQUEUE`, `RLIMIT_SIGPENDING`, `RLIMIT_CPU`, `RLIMIT_RTTIME`,
  `RLIMIT_NICE`, `RLIMIT_RTPRIO`, and `RLIMIT_LOCKS` pressure emit
  structured resource pressure audit events in QEMU
- `RLIMIT_LOCKS` pressure is conflict/denial telemetry for BSD `flock()` and
  POSIX/OFD lock acquisition failures, not fake quota enforcement
- over-permissive System V IPC and POSIX mqueue access denied across uid/gid
- direct raw block-device opens denied without block-device authority
- raw block-device query can be allowed without granting block-device admin
  ioctls or block io_uring discard
- io_uring SQPOLL setup and selected restricted registrations are denied
  without io_uring restricted-operation authority
- `kernel.io_uring_disabled` reports as locked in status and cannot be lowered
  after being tightened
- `kernel.modules_disabled` and `kernel.kexec_load_disabled` cannot be lowered
  after being tightened
- new USB device attachment denied without USB attach authority
- usbmon capture denied without USB monitor authority
- cross-profile signal sends denied without signal authority
- system time mutation denied without time administration authority
- hard resource-limit raises denied without resource administration authority
- successful fork/clone/vfork operations emit structured fork audit events
- policy learning turns denied event records into reviewable authority and
  memory-policy suggestions while keeping W+X invariant denials review-only
- policy merge turns reviewed learner output into a compiler-accepted candidate
  policy and refuses suggestions for profiles missing from the base policy
- network blackhole and TCP simultaneous-connect mitigations report enabled
  status
- loopback closed TCP/UDP behavior remains diagnostic when network blackhole is
  enabled
- non-loopback closed TCP/UDP responses are suppressed when network blackhole
  is enabled
- anonymous `MAP_STACK` and `MAP_GROWSDOWN` mappings receive varied
  page-aligned random placement gaps when ASLR is enabled
- sealed mitigation status reports vmapped kernel stacks, separated
  `thread_info`, and strong stack protector
- kernel lockout reports enabled status, bans a non-root uid through the
  policy-admin probe, kills that uid's live task, and blocks later credential
  reentry for that uid

### Exec Identity

- signed system binary gets system profile
- unsigned user binary gets user profile
- compiler roles expand inherited reusable grants into sealed profiles
- UID/GID subject rules select account profiles
- profile umask floors keep subject-selected file and directory creation private
- signed exec inheritance preserves caller profiles and parent-scoped inheritance
  ignores unmatched callers
- signed object read/write/delete/create/creat/mkdir/mknod/symlink/unlink/rmdir/exec/link/link-target/attr/chmod/chown/utime/setid/xattr/setxattr/removexattr/access/stat/list/find/ioctl/lock/watch/receive/fcntl/chdir/mount/mount-source/umount/truncate/rename/rename-target/unix-connect/unix-bind/unix-listen/unix-accept/unix-send/unix-recv, append-only, recursive split-operation tree, recursive descriptor, operation-tree, target-tree, and preopened-descriptor unmatched checks, fd-receive, mount topology with unmatched-target and source checks, split metadata/xattr, and filesystem-socket IPC operation tree, and recursive append-only tree rules constrain protected file, executable, metadata, setid-bit, extended-attribute, directory-entry, lookup/open, fd-passing, descriptor-control, working-directory, mount topology, size/extent mutation, move access, and filesystem socket IPC by resolved identity
- script inherits correct interpreter-chain profile
- non-root TPE denies execution from unsafe executable directories
- setuid transition gets privileged profile only when valid
- file capability transition is mediated
- unprivileged privileged-helper exec denial works independently of target
  `CRED_CHANGE`
- process-accounting audit is profile-scoped and records exit status without
  enabling global exit logging
- modified trusted binary loses trust

### Sealing

- policy table cannot mutate after commit
- module text cannot become writable after finalization
- sealed HDN data write faults trigger events
- hook tables become read-only after init

### Recovery

- bad policy rollback works
- bad driver approval can be reverted
- known-good boot works
- logs survive recovery transition

### Regression

- normal desktop boot works
- browser works
- media apps work
- game profile works
- developer mode works
- virtualization profile works
- package updates work
- suspend/resume works

## Implementation Sequence

### Phase 0: Policy and Harness

- Define profile schema.
- Define authority list.
- Define audit event schema.
- Build harness around expected outcomes.
- Build userspace policy compiler prototype.
- Build userspace policy-learning output from stable event records.
- Build userspace policy-merge output from reviewed learner suggestions.
- Build a named policy workflow facade and policy daemon above learning, merge,
  compile, and brokered signed commit helpers.
- Build userspace status output from stable status records.
- Build a product ROFS apply helper for post-boot read-only mount sealing.
- Build a product ROFS transaction helper for package/update/recovery writes
  that must reseal before returning.
- Build a package-manager hook facade above named transactions and image seals,
  with shipped package-manager and image-seal hook snippets.
- Build recovery session and portal facades above named recovery actions so
  recovery UI has one stable product contract.

### Phase 1: Upstream-Hardening Baseline

- Configure existing kernel hardening options.
- Lock down BPF, perf, ptrace, user namespaces, debugfs, tracefs, procfs, module loading, kexec, and kernel log reads/writes through available upstream controls and HDN authorities.
- Integrate Secure Boot, module signing, fs-verity, IMA/IPE/AppArmor/SELinux/Landlock where appropriate.
- Build the graphical prompt daemon and settings panel on top of the
  control-center and desktop-daemon contracts for normal desktop action
  requests, on the prompt-session contract when the product frontend needs to
  select its own session backend, or on the lower-level prompt-describe and
  prompt-dispatch contracts when the frontend needs to own authentication
  directly. Keep metadata, token, and broker details behind those root-side
  facades.

### Phase 2: Authority Gates

- Add central authority gate API.
- Convert selected dangerous subsystems to call authority gates.
- Emit structured audit events.
- Keep policy simple and profile-based.
- Keep local desktop IPC out of network authority gates unless product policy
  explicitly asks to restrict it.

### Phase 3: Exec Profiles

- Attach sealed profiles at exec.
- Implement interpreter-chain handling.
- Add file identity cache.
- Connect package/app identity to profile selection.
- Throttle repeated crash signals from privileged exec transitions by file
  identity, target profile, and uid.
- Add a profile feature that denies unprivileged setuid, setgid, secureexec,
  and file-capability helper execution before credential commit.

### Phase 4: Memory Policy

- Add `mmap`/`mprotect` request rewrite hooks.
- Enforce W^X and JIT profiles.
- Lock anonymous memfd execution defaults to enforced noexec mode.
- Implement compatibility exceptions as explicit profile grants or trusted, versioned executable metadata.

### Phase 5: Sealing

- Add phase model.
- Seal policy tables.
- Seal hook tables.
- Verify module text/rodata transitions.
- Add invariant violation response beyond reporting.

### Phase 6: Compiler and Object Hardening

- Add build-time checks.
- Adopt upstream CFI/KCFI and hardening options where possible.
- Add original small passes only where unavoidable.
- Expand Rust use in policy-facing kernel code where practical.

## Comparison Against Giant Patch Architecture

The giant-patch approach tends to:

- add direct calls throughout unrelated subsystems
- mix memory policy, RBAC, logging, learning, and exploit response
- require broad compiler-plugin machinery
- encode product policy inside kernel call sites
- make long-term rebasing expensive
- make user-facing integration an afterthought

This design instead:

- installs narrow transition hooks
- attaches sealed profiles
- centralizes authority checks
- keeps policy in userspace
- makes audit structured
- makes recovery first-class
- keeps desktop authorization separate from kernel enforcement
- lets the distro own product semantics

## Open Questions

- Which LSM pieces should be reused directly, and which need new hardening-specific hooks because rewrite decisions are required?
- What is the minimal profile schema that can cover desktop, developer, gaming, and virtualization use cases?
- How much policy should be loaded into the kernel versus kept in userspace with kernel-side caching?
- What is the best stable identity source for user-installed apps across filesystems?
- Which JIT exceptions should live in app profiles, and which should be represented as trusted executable metadata?
- Which authority gates need per-namespace state?
- What is the exact recovery root of trust on machines without reliable Secure Boot?
- Which compiler-hardening gaps remain after using upstream kernel and compiler features?

## Design Summary

This hardening suite should behave like an OS security plane, not like a pile of kernel toggles.

The kernel enforces invariants, mediates dangerous transitions, attaches sealed profiles, and centralizes authority checks. Userspace owns policy language, app identity, authorization prompts, audit presentation, and recovery.

The net effect should match the security classes people historically used heavy hardening patches for: exploit mitigation, attack-surface reduction, trusted execution, and strict privileged transitions. The implementation shape should be cleaner, smaller at each call site, easier to rebase, easier to test, and directly integrated into a normal consumer OS.
