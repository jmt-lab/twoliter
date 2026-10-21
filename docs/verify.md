# How `twoliter verify` works

`twoliter verify ami` and `twoliter verify kit` answer one question: **was this published artifact
built from the source it claims?** Both rebuild the artifact from that source and compare the result
against what was published, treating the published copy as untrusted input.

## Flow

Both commands share the same shape: resolve → fetch → rebuild → compare → report.

| Step | `verify ami --ami-id <id>` | `verify kit <kit> <version>` |
|---|---|---|
| Resolve | Read variant, arch, version and commit from the AMI name / snapshot description. Reject dirty builds. | Fetch the OCI index for `<registry>/<kit>:v<version>`; read the kit name and version from the image config label; find the commit tagged `v<version>` (or `--commit`). |
| Fetch | Download the root and data snapshots with coldsnap (copying cross-account snapshots first, deleting the copies after). | Pull each architecture's image into an OCI layout. Fail early if the image's creation time is not the commit's time (the kit was built from another commit). |
| Rebuild | Check out the commit and run `cargo make` so the image is built with the twoliter pinned in the repo. Runs in parallel with the download. | Check out the commit, pull the SDK pinned in `Twoliter.lock` for `--sdk-arch`, and run `make build KIT=<kit> ARCH=<arch>` per architecture. |
| Compare | `reprosys compare` on the two disk images, region by region. | Compare manifest digests; on mismatch, config fields, then layers, then each differing RPM with `reprosys compare-rpm`. |
| Report | Terminal summary (failures first, expected differences counted), `report.json`, `log.jsonl`. Exit non-zero unless `verified`. | Same, without `log.jsonl`. |

The comparison runs in `reprosys`, a tool embedded in twoliter that reads every format itself
(GPT, ext4, erofs, FAT, dm-verity, RPM headers and cpio payloads, ELF notes, PE sections) from the
raw bytes, without mounting or root.

## What is checked

A rebuild cannot be byte-identical: release signing keys are not available, so each build signs
with fresh keys. The tool therefore has a short, explicit list of *expected* differences and treats
everything else as a failure.

**AMI, per disk region**

| Region | Rule |
|---|---|
| GPT, PRIVATE, BIOS-boot, DATA, data image | Byte-identical. B-bank, RESERVED and padding must be zero. A differing PRIVATE still fails, but its directory hash flag (taken by mke2fs from the build host) and file contents are compared to explain why, with lines of `bootconfig.data` found on only one side shown in the report. |
| ROOT-A (erofs only) | If bytes differ, compare the file trees: type, mode, owner, symlink target, device numbers, xattrs (SELinux labels, capabilities), contents. Other root filesystem formats are not supported. Expected: kernel module signatures, the TUF root role (`/usr/share/updog/root.json`, whose published digest/keys are printed to check by hand), and the SBOMs (`/usr/share/bottlerocket/{spdx,cyclonedx}-sbom.json`) as long as both list the same packages by name and version, since sbomtool's output is not reproducible yet. |
| BOOT-CONFIG (`grub.cfg` in BOOT-A, or for UKI images, which have no BOOT-A, the UKI's `.cmdline` section in EFI-A) | Identical except the dm-verity root hash and salt; exactly one verity table for the same devices. |
| HASH-A | Not compared: it is formatted with a random salt, so it never matches the rebuilt one. The root hash and salt it is built with are the fields BOOT-CONFIG allows to differ. |
| EFI-A, BOOT-A | If bytes differ, file by file, and every difference needs a listed cause or verification fails: a signature or certificate that both images have; a PE binary whose Authenticode digest matches, or that differs only in its key-holding sections (`.vendor_cert`, `.pubkey`) with the same headers and layout; a FIPS `.hmac` that is the HMAC of the published file it names; the verity root hash and salt in `grub.cfg` or the UKI's `.cmdline`. Files in only one image fail, which also keeps out the add-ons, credentials and extension images systemd-stub would load next to a UKI. The kernel comes from the kit, so it must match apart from its signature. |

**Kit, per architecture**

| Level | Rule |
|---|---|
| Manifest | Identical digest ⇒ verified; nothing else to look at. |
| Config | Every field compared, with the kit metadata label decoded. |
| Layers | Matched by the package directory or `repodata` they hold. Each tar entry compared by type, contents, mode, owner, mtime, link target. |
| RPM | Header tags compared one by one (except those derived from the payload); each payload checked against its own header's digests; payload files compared like ROOT-A. Expected: module signatures (note), kernel image and signing cert (warn), Go binaries differing only in build-ID notes (note). |
| repodata | Expected to differ only when some package differs in expected ways, and only in contents or checksum-named filenames. |

## Why this way

- **Verifies the published bytes, not a view of them.** Parsing in userspace means the tool sees
  exactly what was published. Mounting would show what the host kernel chooses to present (journal
  replay, SELinux relabeling, uid remapping, missing erofs features), which varies by host.
- **No privilege for untrusted input.** The published image is the thing under suspicion. It is
  never handed to the kernel's filesystem drivers as root; readers are bounded by explicit size
  limits so a crafted image can only produce an error.
- **Covers the security chain, not just files.** Secure Boot binaries and the dm-verity table in
  `grub.cfg` or the UKI's `.cmdline` live outside any filesystem tree. Checking them from raw
  partitions is what shows the published image boots with the same configuration as the rebuilt
  one.
- **Expected differences are enumerated, not inferred.** Each tolerated difference names a cause
  (per-build signing key, release-only TUF keys, a Go toolchain bug). Any difference without a
  listed cause fails, so a verdict of `verified` is a strong statement.
- **Rebuilds with the pinned toolchain.** Running the repo's own `cargo make` / `make build` with
  the SDK from `Twoliter.lock` removes the verifier's environment as a source of difference, so a
  failure points at the source or the published artifact, not the machine running the check.
- **Explains failures.** Every differing file is listed with what differs, so a mismatch is
  actionable without unpacking images by hand.

See [Verifying an AMI](../README.md#verifying-an-ami) and [Verifying a kit](verify-kit.md) for
the full option reference and rule details.
