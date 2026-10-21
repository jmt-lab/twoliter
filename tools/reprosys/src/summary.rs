//! The comparison report, summarized for the terminal.

use crate::ami::AmiInfo;
use crate::compare::{RegionReport, Report, Verdict};
use crate::fsfiles::Status;

/// Hex strings at least this long are shortened in the summary; the report has them in full.
const LONG_HASH: usize = 32;

/// Width the summary's prose is wrapped to.
const WRAP_WIDTH: usize = 100;

impl RegionReport {
    /// The summary's marker for this region, and its rank: failures are listed first.
    fn marker(&self) -> (&'static str, u8) {
        match (self.status, self.fatal) {
            (Status::Match, _) => ("ok", 3),
            (Status::ExpectedDifference, _) => ("note", 2),
            (Status::Warning, _) => ("warn", 1),
            (Status::Mismatch, true) => ("FAIL", 0),
            (Status::Mismatch, false) => ("warn", 1),
        }
    }
}

/// Render the comparison report for the terminal.
pub fn summary(report: &Report, info: &AmiInfo, verbose: bool) -> String {
    let mut out = Vec::new();
    let shorten = |text: &str| {
        if verbose {
            text.to_string()
        } else {
            shorten_hashes(text)
        }
    };
    out.push(String::new());
    out.push(format!(
        "Verification of {} ({} {} v{}, commit {})",
        info.ami_id, info.variant, info.arch, info.version, info.build_id
    ));

    let mut root_role = None;
    let images = std::iter::once(("OS image", &report.os))
        .chain(report.data.as_ref().map(|d| ("Data image", d)));
    for (title, image) in images {
        out.push(String::new());
        out.push(title.to_string());
        let mut regions: Vec<&RegionReport> = image.regions.iter().collect();
        regions.sort_by_key(|r| r.marker().1);
        let (identical, differing): (Vec<_>, Vec<_>) =
            regions.into_iter().partition(|r| r.status == Status::Match);
        for region in differing {
            out.push(format!(
                "  {:<5} {:<12} {}",
                region.marker().0,
                region.name,
                shorten(&region.detail)
            ));
            let mut hidden = 0;
            for file in region.files.iter().filter(|f| f.status != Status::Match) {
                if file.root_role.is_some() {
                    root_role = file.root_role.as_ref();
                }
                if file.status == Status::Mismatch {
                    out.push(format!("          {}", file.path));
                    out.push(format!("            {}", shorten(&file.detail)));
                } else if verbose {
                    out.push(format!("          {}", file.path));
                    out.push(format!("            expected difference: {}", file.detail));
                } else {
                    hidden += 1;
                }
            }
            if hidden > 0 {
                let s = if hidden == 1 { "" } else { "s" };
                out.push(format!(
                    "          + {hidden} expected difference{s} (shown with --verbose)"
                ));
            }
        }
        if !identical.is_empty() {
            let names: Vec<&str> = identical.iter().map(|r| r.name.as_str()).collect();
            out.push(format!(
                "  {:<5} {}",
                "ok",
                wrap(&format!("{} identical", names.join(", ")), 8)
            ));
        }
    }

    if let Some(role) = root_role {
        out.push(String::new());
        out.push("Check by hand".to_string());
        out.push(format!(
            "  {}",
            wrap(
                "The TUF root role (/usr/share/updog/root.json) cannot be rebuilt without the \
                 release keys. Check that the AMI's root role is the one your repository \
                 publishes (for Bottlerocket, https://cache.bottlerocket.aws/root.json):",
                2
            )
        ));
        let first_key = role.keys.first().map_or("", String::as_str);
        for (label, value) in [
            ("sha512", role.sha512.as_str()),
            ("version", &role.version),
            ("expires", &role.expires),
            ("keys", first_key),
        ] {
            out.push(format!("    {label:<8} {value}"));
        }
        for key in role.keys.iter().skip(1) {
            out.push(format!("    {:<8} {key}", ""));
        }
    }

    out.push(String::new());
    if verbose {
        for note in &report.notes {
            out.push(format!("Note: {}", wrap(note, 6)));
        }
    } else {
        out.push(wrap(
            "FAIL fails verification. note marks differences that per-build signing keys, \
             random salts or the build host's architecture explain; they do not fail \
             verification. The report explains each check, and --verbose shows more detail.",
            0,
        ));
    }

    out.push(String::new());
    let failed: Vec<&str> = std::iter::once(&report.os)
        .chain(&report.data)
        .flat_map(|image| &image.regions)
        .filter(|r| r.failed())
        .map(|r| r.name.as_str())
        .collect();
    if report.verdict == Verdict::Verified {
        out.push("Result: VERIFIED".to_string());
    } else if failed.is_empty() {
        out.push("Result: FAILED".to_string());
    } else {
        out.push(format!(
            "Result: FAILED ({} differ{} from the rebuilt image)",
            failed.join(", "),
            if failed.len() == 1 { "s" } else { "" }
        ));
    }
    out.push(String::new());
    out.join("\n")
}

/// Shorten hex strings of at least `LONG_HASH` characters to their first 12.
fn shorten_hashes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(|c: char| c.is_ascii_hexdigit()) {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let len = rest
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        if len >= LONG_HASH {
            out.push_str(&rest[..12]);
            out.push('…');
        } else {
            out.push_str(&rest[..len]);
        }
        rest = &rest[len..];
    }
    out.push_str(rest);
    out
}

/// Wrap `text` to `WRAP_WIDTH`, indenting continuation lines by `indent` spaces.
fn wrap(text: &str, indent: usize) -> String {
    let mut out = String::new();
    let mut column = indent;
    for word in text.split_whitespace() {
        if column > indent && column + 1 + word.len() > WRAP_WIDTH {
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            column = indent;
        } else if column > indent {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += word.chars().count();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::ImageReport;
    use crate::disk::Policy;
    use crate::fsfiles::{FileReport, RootRole};

    const SHA: &str = "a9f9a4d30f465f0846e4d73f6d77ad669100410ef5241097ea40932329a1f99f";

    fn file(path: &str, status: Status, detail: &str) -> FileReport {
        FileReport {
            path: path.to_string(),
            status,
            detail: detail.to_string(),
            root_role: None,
        }
    }

    fn region(name: &str, status: Status, detail: &str, files: Vec<FileReport>) -> RegionReport {
        RegionReport {
            name: name.to_string(),
            policy: Policy::MustMatch,
            status,
            fatal: true,
            offset: 0,
            len: 0,
            expected_sha256: None,
            actual_sha256: None,
            detail: detail.to_string(),
            files,
        }
    }

    fn image(regions: Vec<RegionReport>) -> ImageReport {
        ImageReport {
            expected: None,
            actual: None,
            expected_len: 0,
            actual_len: 0,
            regions,
        }
    }

    fn report(root_a_status: Status) -> Report {
        use Status::{ExpectedDifference as Expected, Match, Mismatch};
        let root_role = FileReport {
            root_role: Some(RootRole {
                sha512: format!("{SHA}{SHA}"),
                version: "1".to_string(),
                expires: "2027-10-12T17:12:35Z".to_string(),
                keys: vec![SHA.to_string()],
            }),
            ..file(
                "/x86_64-bottlerocket-linux-gnu/sys-root/usr/share/updog/root.json",
                Expected,
                &format!(
                    "TUF root role; rebuilds generate their own because the release root role \
                     keys are not available. Check the published root role against the one \
                     your repository publishes: sha512 {SHA}{SHA}, version 1, expires \
                     2027-10-12T17:12:35Z, keys {SHA}"
                ),
            )
        };
        let mut root_files = vec![root_role];
        if root_a_status == Mismatch {
            root_files.push(file(
                "/x86_64-bottlerocket-linux-gnu/sys-root/usr/lib/settings-plugins/aws-dev/libsettings.so",
                Mismatch,
                &format!("contents differ (3539600 bytes, sha256 {SHA} vs 3539152 bytes, sha256 {SHA})"),
            ));
        }
        let signing = "files differ only in signing-dependent content";
        Report {
            verdict: if root_a_status == Mismatch {
                Verdict::Failed
            } else {
                Verdict::Verified
            },
            os: image(vec![
                region("GPT", Match, "identical", vec![]),
                region(
                    "EFI-A",
                    Expected,
                    signing,
                    vec![
                        file(
                            "/EFI/BOOT/grubx64.efi",
                            Expected,
                            "differs only in sections holding embedded keys (.pubkey)",
                        ),
                        file("/EFI/BOOT/db.crt", Expected, "signing artifact"),
                    ],
                ),
                region(
                    "BOOT-A",
                    Expected,
                    signing,
                    vec![
                        file("/vmlinuz", Expected, "signatures differ"),
                        file("/grub/grub.cfg.sig", Expected, "signing artifact"),
                    ],
                ),
                region("ROOT-A", root_a_status, "differing files", root_files),
                region("PRIVATE", Match, "identical", vec![]),
            ]),
            data: Some(image(vec![region("DATA", Match, "identical", vec![])])),
            notes: vec!["A note.".to_string()],
        }
    }

    fn info() -> AmiInfo {
        serde_json::from_value(serde_json::json!({
            "ami_id": "ami-1", "ami_name": "bottlerocket", "name": "bottlerocket",
            "variant": "aws-dev", "arch": "x86_64", "version": "1.67.0", "build_id": "d2569283",
            "filename_prefix": "bottlerocket", "root_snapshot": "snap-1", "data_snapshot": null,
            "owner": "123", "owned_by_caller": true,
        }))
        .unwrap()
    }

    #[test]
    fn summary_lists_failures_first_and_hides_expected_differences() {
        let text = summary(&report(Status::Mismatch), &info(), false);
        let lines: Vec<&str> = text.lines().collect();
        let position = |prefix: &str| {
            lines
                .iter()
                .position(|l| l.trim_start().starts_with(prefix))
                .unwrap_or_else(|| panic!("no line starting with {prefix:?} in:\n{text}"))
        };
        assert!(position("FAIL  ROOT-A") < position("note  EFI-A"));
        assert!(position("note  EFI-A") < position("note  BOOT-A"));
        assert!(position("note  BOOT-A") < position("ok    GPT, PRIVATE identical"));
        assert!(text.contains("  ok    DATA identical"));
        assert!(text.contains("aws-dev/libsettings.so"));
        assert!(!text.contains("/EFI/BOOT/grubx64.efi"));
        assert!(!text.contains("/EFI/BOOT/db.crt"));
        assert!(text.contains("+ 2 expected differences (shown with --verbose)"));
        assert!(text.contains("sha256 a9f9a4d30f46… vs"));
        // The root role is listed in full to check by hand.
        assert!(text.contains(&format!("\n    sha512   {SHA}{SHA}\n    version  1\n")));
        assert!(text.contains(&format!("\n    keys     {SHA}\n")));
        assert!(!text.contains("Note: A note."));
        assert!(text.ends_with("Result: FAILED (ROOT-A differs from the rebuilt image)\n"));
    }

    #[test]
    fn verbose_summary_lists_everything() {
        let text = summary(&report(Status::ExpectedDifference), &info(), true);
        assert!(text.contains("/EFI/BOOT/db.crt"));
        assert!(text.contains("expected difference: signing artifact"));
        assert!(!text.contains('…'));
        assert!(text.contains("Note: A note."));
        assert!(text.contains("Check by hand"));
        assert!(text.ends_with("Result: VERIFIED\n"));
    }

    #[test]
    fn shortens_only_long_hashes() {
        let long = "d91c430f8a647c11171f08308a21275f61fc991267a092253108bd24ae074fb6";
        assert_eq!(
            shorten_hashes(&format!("root hash {long}; snap-012c07623fe00054c")),
            "root hash d91c430f8a64…; snap-012c07623fe00054c"
        );
    }

    #[test]
    fn wraps_with_indent() {
        let text = "word ".repeat(30);
        let wrapped = wrap(&text, 4);
        assert!(wrapped.lines().all(|l| l.len() <= WRAP_WIDTH));
        assert!(wrapped.lines().skip(1).all(|l| l.starts_with("    w")));
        assert_eq!(wrapped.split_whitespace().count(), 30);
    }
}
