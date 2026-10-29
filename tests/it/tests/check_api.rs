use std::{
    fs,
    io::{self, Write},
    path::Path,
    process::{Command, Output, Stdio},
};

use gix_testtools::TestResult;
use serde_json::{Value, json};

fn check_api(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_it"));
    gix_testtools::configure_git_environment(&mut command, directory);
    command
        .current_dir(directory)
        .arg("check-api")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn assert_exit(output: &Output, expected: i32, reason: &str) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{reason}; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn public_function_document() -> Value {
    json!({
        "format_version": 61,
        "includes_private": false,
        "root": 0,
        "external_crates": {"1": {"name": "public_dep"}},
        "paths": {"10": {"crate_id": 1, "path": ["public_dep", "Item"]}},
        "index": {
            "0": {"name": "api", "crate_id": 0, "visibility": "public",
                "inner": {"module": {"items": [1]}}},
            "1": {"name": "read", "crate_id": 0, "visibility": "public",
                "inner": {"function": {
                    "sig": {"inputs": [], "output": {"resolved_path": {"id": 10, "path": "Item"}}},
                    "generics": {"params": [], "where_predicates": []}
                }}}
        }
    })
}

#[test]
fn audit_reports_public_dependencies_with_or_without_an_allowlist() -> TestResult {
    let directory = gix_testtools::tempfile::tempdir()?;
    fs::write(
        directory.path().join("api.json"),
        serde_json::to_vec(&public_function_document())?,
    )?;

    for allowlist in [None, Some("unused_dep,public_dep")] {
        let mut command = check_api(directory.path());
        command.args(["audit", "api.json"]);
        if let Some(allowlist) = allowlist {
            command.arg(allowlist);
        }
        let output = command.output()?;
        assert_exit(
            &output,
            0,
            "audits pass when no allowlist is given or all public dependencies are allowed",
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout)?,
            json!({"public_dep": ["public_dep::Item"]}),
            "audit stdout identifies the external type exposed by the public function"
        );
    }
    Ok(())
}

#[test]
fn audit_allowlist_violation_is_a_completed_check() -> TestResult {
    let directory = gix_testtools::tempfile::tempdir()?;
    fs::write(
        directory.path().join("api.json"),
        serde_json::to_vec(&public_function_document())?,
    )?;

    let output = check_api(directory.path())
        .args(["audit", "api.json", "other_dep"])
        .output()?;
    assert_exit(
        &output,
        10,
        "an exposed dependency outside the allowlist is a violation, not a tool failure",
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?,
        json!({"public_dep": ["public_dep::Item"]}),
        "a failed allowlist still reports the public dependency that caused the violation"
    );
    Ok(())
}

#[test]
fn audit_rejects_malformed_json() -> TestResult {
    let directory = gix_testtools::tempfile::tempdir()?;
    fs::write(directory.path().join("api.json"), b"not JSON")?;

    let output = check_api(directory.path()).args(["audit", "api.json"]).output()?;
    assert_exit(&output, 2, "malformed rustdoc JSON cannot produce an audit verdict");
    assert!(
        !output.stderr.is_empty(),
        "malformed JSON has an actionable error on stderr"
    );
    assert!(
        output.stdout.is_empty(),
        "malformed JSON must not emit a successful dependency report"
    );
    Ok(())
}

#[test]
fn audit_fails_closed_for_unsupported_rustdoc_documents() -> TestResult {
    let directory = gix_testtools::tempfile::tempdir()?;
    for (case, diagnostic) in [("format", "61"), ("private", "private"), ("item kind", "future_kind")] {
        let mut document = public_function_document();
        match case {
            "format" => document["format_version"] = json!(62),
            "private" => document["includes_private"] = json!(true),
            _ => document["index"]["1"]["inner"] = json!({"future_kind": {}}),
        }
        fs::write(directory.path().join("api.json"), serde_json::to_vec(&document)?)?;

        let output = check_api(directory.path()).args(["audit", "api.json"]).output()?;
        assert_exit(
            &output,
            2,
            &format!("unsupported rustdoc {case} must fail rather than silently omit dependencies"),
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(diagnostic),
            "the diagnostic identifies the unsupported rustdoc {case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "unsupported rustdoc {case} must not emit a dependency report"
        );
    }
    Ok(())
}

fn with_stdin(command: &mut Command, input: &[u8]) -> io::Result<Output> {
    let mut child = command.stdin(Stdio::piped()).spawn()?;
    child
        .stdin
        .take()
        .expect("the release request input was piped")
        .write_all(input)?;
    child.wait_with_output()
}

#[test]
fn release_mode_rejects_invalid_stdin_with_or_without_a_baseline_root() -> TestResult {
    let directory = gix_testtools::tempfile::tempdir()?;
    fs::create_dir(directory.path().join("baseline"))?;

    for args in [&[][..], &["--baseline-root", "baseline"][..]] {
        for input in [b"not JSON".as_slice(), b"{}".as_slice()] {
            let output = with_stdin(check_api(directory.path()).args(args), input)?;
            assert_exit(
                &output,
                2,
                "malformed JSON or missing release request fields cannot complete a release check",
            );
            assert!(
                !output.stderr.is_empty(),
                "invalid release requests explain the failure on stderr"
            );
            assert!(
                output.stdout.is_empty(),
                "invalid release requests must not emit a compatibility verdict"
            );
        }
    }
    Ok(())
}

#[test]
fn audit_rejects_release_only_arguments() -> TestResult {
    let directory = gix_testtools::tempfile::tempdir()?;
    let output = check_api(directory.path())
        .args(["--baseline-root", "baseline", "audit", "api.json"])
        .output()?;
    assert_exit(&output, 2, "the baseline override belongs only to release checks");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot be used"),
        "the conflict is rejected before either mode accesses the filesystem"
    );
    Ok(())
}

#[test]
fn help_describes_release_and_audit_modes_without_reading_stdin() -> TestResult {
    let directory = gix_testtools::tempfile::tempdir()?;
    for args in [&["--help"][..], &["audit", "--help"][..]] {
        let output = check_api(directory.path()).args(args).output()?;
        assert_exit(
            &output,
            0,
            "release and audit help succeed without a request or rustdoc document",
        );
        let help = String::from_utf8(output.stdout)?;
        assert!(
            help.contains("Usage:"),
            "help provides command usage rather than an audit report"
        );
        assert!(help.contains("audit"), "help identifies the audit subcommand");
        if args == ["--help"] {
            assert!(
                help.contains("--baseline-root"),
                "release help documents the baseline checkout override"
            );
        }
    }
    Ok(())
}

#[test]
fn boundary_uses_manifest_exceptions_and_resolved_dependency_features() -> TestResult {
    let directory = gix_testtools::tempfile::tempdir()?;
    let root = directory.path();
    for crate_name in ["consumer", "plumbing"] {
        fs::create_dir_all(root.join(crate_name).join("src"))?;
    }
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"consumer\", \"plumbing\"]\nresolver = \"2\"\n",
    )?;
    fs::write(
        root.join("plumbing/Cargo.toml"),
        r#"
[package]
name = "plumbing"
version = "0.1.0"
edition = "2024"
[features]
unstable = []
leak = []
[dev-dependencies]
plumbing = { path = ".", features = ["leak"] }
"#,
    )?;
    fs::write(
        root.join("plumbing/src/lib.rs"),
        r#"
pub struct Basic;
pub struct Experimental;
impl Basic {
    #[cfg(feature = "unstable")]
    #[doc = "\n\n**Unstable.**"]
    pub fn experimental(&self) -> Experimental { Experimental }
    #[cfg(feature = "leak")]
    pub fn supported(&self) -> Experimental { Experimental }
}
"#,
    )?;
    fs::write(
        root.join("consumer/src/lib.rs"),
        "pub fn read() -> plumbing::Basic { plumbing::Basic }\n",
    )?;
    let manifest = |recursive: bool, features: &str| {
        format!(
            r#"
[package]
name = "consumer"
version = "1.0.0"
edition = "2024"
[dependencies]
plumbing = {{ path = "../plumbing", features = ["unstable"{features}] }}
[package.metadata.api-check]
profiles = [{{ default-features = false, features = [] }}]
allowed-unstable-types = ["plumbing::Basic"]
recursive = {recursive}
"#
        )
    };
    for (recursive, features, expected, reason) in [
        (
            true,
            "",
            0,
            "unified experimental methods remain outside the supported API",
        ),
        (
            true,
            ", \"leak\"",
            10,
            "resolved dependency features expose an unlisted type through a supported method",
        ),
        (
            false,
            ", \"leak\"",
            0,
            "direct checks do not recursively promise dependency members",
        ),
    ] {
        fs::write(root.join("consumer/Cargo.toml"), manifest(recursive, features))?;
        let output = check_api(root)
            .env("CARGO_TARGET_DIR", root.join("target"))
            .args(["boundary", "consumer/Cargo.toml"])
            .output()?;
        assert_exit(&output, expected, reason);
    }
    Ok(())
}
