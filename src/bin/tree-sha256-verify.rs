//! Verify a tag made by `tree-sha256-tag`.
//!
//! Checks that the tag's SSH signature is valid (via `git verify-tag`, so
//! `gpg.ssh.allowedSignersFile` decides which keys are trusted) and that its
//! `tree-sha256` header matches a fresh hash of the tagged tree's contents.
//! Submodules named in `tree-sha256-excluded` headers are left out exactly as
//! they were when signing, and reported as not verifiable.
//! The signature check runs in a child process while the tree is hashed.
//!
//! Usage: tree-sha256-verify [--repo <path>] [--no-signature] <tag>

use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use tree_sha256::{EXCLUDED_HEADER, HEADER, Options, hex, parse_args, tree_sha256};

const USAGE: &str = "tree-sha256-verify [--repo <path>] [--no-signature] <tag>";

fn main() -> Result<()> {
    let mut check_signature = true;
    let (repo_path, positional) = parse_args(USAGE, |flag, _| {
        match flag {
            "--no-signature" => check_signature = false,
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let [tag] = positional.as_slice() else {
        bail!("usage: {USAGE}");
    };

    let repo = gix::open(&repo_path).with_context(|| format!("opening {repo_path}"))?;
    let total = Instant::now();

    let tag_id = repo
        .rev_parse_single(tag.as_str())
        .with_context(|| format!("resolving {tag}"))?
        .detach();
    let tag_obj = repo.find_object(tag_id)?;
    if tag_obj.kind != gix::object::Kind::Tag {
        bail!("{tag} is a {}, not an annotated tag", tag_obj.kind);
    }

    // Verify the exact object we parse, by id, so the ref can't move under us.
    let verifier = check_signature
        .then(|| {
            Command::new("git")
                .arg("--git-dir")
                .arg(repo.git_dir())
                .args(["verify-tag", &tag_id.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .context("running git verify-tag")
        })
        .transpose()?;

    let headers = parse_headers(&tag_obj.data)?;
    let opts = Options {
        exact: headers.excluded.clone(),
        ..Options::default()
    };

    let t = Instant::now();
    let hashed = tree_sha256(&repo, headers.object, &opts)?;
    let hash_time = t.elapsed();
    let actual = hex(&hashed.digest);

    let signature_ok = match verifier {
        Some(child) => {
            let out = child.wait_with_output()?;
            eprint!("{}", String::from_utf8_lossy(&out.stderr));
            Some(out.status.success())
        }
        None => None,
    };

    // Every excluded path in the tag must really be a submodule of this tree.
    let found: Vec<&str> = hashed.excluded.iter().map(|(p, _)| p.as_str()).collect();
    let bogus: Vec<&String> = headers
        .excluded
        .iter()
        .filter(|p| !found.contains(&p.as_str()))
        .collect();

    let tree_ok = actual == headers.claimed && bogus.is_empty();
    eprintln!(
        "{} files in {} submodules hashed in {hash_time:.2?}, total {:.2?}",
        hashed.files,
        hashed.submodules,
        total.elapsed()
    );
    if actual != headers.claimed {
        eprintln!(
            "MISMATCH: tag claims {HEADER} {}\n          tree hashes to {actual}",
            headers.claimed
        );
    }
    for path in &bogus {
        eprintln!("MISMATCH: {EXCLUDED_HEADER} {path} is not a submodule in this tree");
    }
    if !hashed.excluded.is_empty() {
        eprintln!(
            "NOT VERIFIABLE: {} submodules were excluded when signing; only their \
             pinned commits are covered, not their contents:",
            hashed.excluded.len()
        );
        for (path, commit) in &hashed.excluded {
            eprintln!("  {path} ({commit})");
        }
    }
    match signature_ok {
        Some(false) => eprintln!("BAD SIGNATURE on {tag_id}"),
        None => eprintln!("signature not checked (--no-signature)"),
        Some(true) => {}
    }
    if tree_ok && signature_ok != Some(false) {
        let partial = if hashed.excluded.is_empty() {
            String::new()
        } else {
            format!(" ({} submodules not verifiable)", hashed.excluded.len())
        };
        println!("OK {tag} {} {HEADER} {actual}{partial}", headers.object);
        Ok(())
    } else {
        std::process::exit(1);
    }
}

struct Headers {
    object: gix::ObjectId,
    claimed: String,
    excluded: Vec<String>,
}

/// Read the tag's header block. It ends at the first blank line, before the
/// message and signature, so everything found here is covered by the signature.
fn parse_headers(data: &[u8]) -> Result<Headers> {
    let mut object = None;
    let mut claimed = None;
    let mut excluded = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        if line.is_empty() {
            break;
        }
        let line = std::str::from_utf8(line).unwrap_or_default();
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        match key {
            "object" => {
                object = Some(
                    gix::ObjectId::from_hex(value.as_bytes())
                        .map_err(|e| anyhow::anyhow!("bad object header '{value}': {e}"))?,
                )
            }
            HEADER if claimed.is_some() => bail!("tag has more than one {HEADER} header"),
            HEADER => claimed = Some(value.to_owned()),
            EXCLUDED_HEADER => excluded.push(value.to_owned()),
            _ => {}
        }
    }
    Ok(Headers {
        object: object.context("tag has no object header")?,
        claimed: claimed.with_context(|| format!("tag has no {HEADER} header"))?,
        excluded,
    })
}
