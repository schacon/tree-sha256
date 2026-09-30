//! Create a signed annotated tag whose object carries a `tree-sha256` header.
//!
//! The header sits after `tagger`, so it is part of the signed payload:
//!
//!     object <commit>
//!     type commit
//!     tag <name>
//!     tagger <ident>
//!     tree-sha256-excluded <path>     (one per excluded submodule, if any)
//!     tree-sha256 <hex>
//!
//!     <message>
//!     -----BEGIN SSH SIGNATURE-----
//!
//! Signing uses SSH with git's `user.signingKey` (and `gpg.ssh.program`), the
//! same way `git tag -s` does with `gpg.format=ssh`, so `git verify-tag`
//! accepts the result.
//!
//! Usage: tree-sha256-tag [--repo <path>] [-m <msg>] [-f]
//!                        [--exclude-submodule <pattern>]... [--exclude-from <file>]
//!                        <tagname> [<rev>]

use std::io::Write as _;
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use gix::objs::Write as _;
use gix::refs::transaction::PreviousValue;
use tree_sha256::{EXCLUDED_HEADER, HEADER, Options, hex, parse_args, tree_sha256};

const USAGE: &str = "tree-sha256-tag [--repo <path>] [-m <msg>] [-f] \
                     [--exclude-submodule <pattern>]... [--exclude-from <file>] <tagname> [<rev>]";

fn main() -> Result<()> {
    let mut message = None;
    let mut force = false;
    let mut opts = Options::default();
    let (repo_path, positional) = parse_args(USAGE, |flag, args| {
        match flag {
            "-m" | "--message" => message = Some(args.next().context("-m needs a message")?),
            "-f" | "--force" => force = true,
            _ => return opts.flag(flag, args),
        }
        Ok(true)
    })?;
    let (name, rev) = match positional.as_slice() {
        [name] => (name.as_str(), "HEAD"),
        [name, rev] => (name.as_str(), rev.as_str()),
        _ => bail!("usage: {USAGE}"),
    };

    let repo = gix::open(&repo_path).with_context(|| format!("opening {repo_path}"))?;
    let total = Instant::now();

    let commit = repo
        .rev_parse_single(rev)
        .with_context(|| format!("resolving {rev}"))?
        .object()?
        .peel_to_commit()?;

    let t = Instant::now();
    let hashed = tree_sha256(&repo, commit.id, &opts)?;
    let hash_time = t.elapsed();
    if let Some((path, _)) = hashed.excluded.iter().find(|(p, _)| p.contains('\n')) {
        bail!("can't record excluded submodule path {path:?} in a tag header");
    }

    let tagger = repo
        .committer()
        .context("no committer identity configured (set user.name and user.email)")??;
    let mut payload = Vec::new();
    writeln!(payload, "object {}", commit.id)?;
    writeln!(payload, "type commit")?;
    writeln!(payload, "tag {name}")?;
    write!(payload, "tagger ")?;
    tagger.write_to(&mut payload)?;
    writeln!(payload)?;
    for (path, _) in &hashed.excluded {
        writeln!(payload, "{EXCLUDED_HEADER} {path}")?;
    }
    writeln!(payload, "{HEADER} {}", hex(&hashed.digest))?;
    writeln!(payload)?;
    let message = message.unwrap_or_else(|| name.to_owned());
    payload.extend_from_slice(message.trim_end().as_bytes());
    payload.push(b'\n');

    let t = Instant::now();
    let signature = sign(&repo, &payload)?;
    let sign_time = t.elapsed();
    payload.extend_from_slice(&signature);

    let t = Instant::now();
    let tag_id = repo
        .objects
        .write_buf(gix::object::Kind::Tag, &payload)
        .map_err(|e| anyhow::anyhow!("writing tag object: {e}"))?;
    let constraint = if force {
        PreviousValue::Any
    } else {
        PreviousValue::MustNotExist
    };
    repo.reference(
        format!("refs/tags/{name}").as_str(),
        tag_id,
        constraint,
        format!("tree-sha256-tag: {name}"),
    )
    .with_context(|| format!("creating refs/tags/{name}"))?;
    let write_time = t.elapsed();

    println!("{tag_id}");
    eprintln!(
        "tagged {} as {name} ({HEADER} {})\n\
         {} files in {} submodules hashed in {hash_time:.2?}, signed in {sign_time:.2?}, \
         written in {write_time:.2?}, total {:.2?}",
        commit.id,
        hex(&hashed.digest),
        hashed.files,
        hashed.submodules,
        total.elapsed(),
    );
    if !hashed.excluded.is_empty() {
        eprintln!(
            "{} submodules excluded and recorded as unverifiable in {EXCLUDED_HEADER} headers",
            hashed.excluded.len()
        );
    }
    if !hashed.cycles.is_empty() {
        eprintln!("{} submodules recorded as cycles", hashed.cycles.len());
    }
    Ok(())
}

/// Produce an SSH signature over `payload` in git's `git` namespace.
fn sign(repo: &gix::Repository, payload: &[u8]) -> Result<Vec<u8>> {
    let config = repo.config_snapshot();
    let key = config
        .string("user.signingKey")
        .context("SSH signing needs user.signingKey")?
        .to_string();
    let program = config
        .string("gpg.ssh.program")
        .map_or_else(|| "ssh-keygen".into(), |p| p.to_string());

    let dir = tempfile::tempdir()?;
    let payload_path = dir.path().join("payload");
    std::fs::write(&payload_path, payload)?;

    // Like git: a literal public key signs through ssh-agent, a path names a
    // private key file (or a public one whose key is in the agent).
    let mut cmd = Command::new(program);
    cmd.args(["-Y", "sign", "-n", "git", "-f"]);
    match key.strip_prefix("key::").or_else(|| key.starts_with("ssh-").then_some(&*key)) {
        Some(literal) => {
            let key_path = dir.path().join("key.pub");
            std::fs::write(&key_path, literal)?;
            cmd.arg(&key_path).arg("-U");
        }
        None => {
            cmd.arg(expand_home(&key));
        }
    }
    let out = cmd.arg(&payload_path).output().context("running ssh-keygen")?;
    if !out.status.success() {
        bail!(
            "ssh-keygen failed to sign the tag:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(std::fs::read(dir.path().join("payload.sig"))?)
}

fn expand_home(path: &str) -> std::path::PathBuf {
    match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => std::path::Path::new(&home).join(rest),
        _ => path.into(),
    }
}
