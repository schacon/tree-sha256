//! SHA-256 digest over every blob in a tree, including checked-out submodules.
//!
//! Each blob's content is read from the object database and hashed with
//! SHA-256. Each submodule's committed tree is hashed the same way, recursively,
//! from the submodule's own repository. The final hash is SHA-256 over one
//! record per entry, ordered by record path (byte order):
//!
//!     <hex sha256 of file content> SP <path> NUL
//!     <hex tree-sha256 of submodule> SP <path> / NUL
//!
//! Tree paths never end in `/` and never contain NUL, so the list is
//! unambiguous and a submodule record can't be mistaken for a file record.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use gix::bstr::{BString, ByteSlice};
use gix::objs::tree::EntryKind;
use gix::prelude::FindExt;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

/// The tag header that carries the digest, e.g. `tree-sha256 <64 hex chars>`.
pub const HEADER: &str = "tree-sha256";

/// Resolve `rev` and hash the tree it points to. Tags and commits are peeled.
pub fn tree_sha256_rev(repo: &gix::Repository, rev: &str) -> Result<([u8; 32], usize)> {
    let id = repo
        .rev_parse_single(rev)
        .with_context(|| format!("resolving {rev}"))?;
    tree_sha256(repo, id.detach())
}

/// Hash every blob in the tree reachable from `id` (a tree, commit or tag),
/// recursing into submodules, and return the combined digest and the number of
/// files hashed. Fails if any submodule isn't checked out, listing all of them.
pub fn tree_sha256(repo: &gix::Repository, id: gix::ObjectId) -> Result<([u8; 32], usize)> {
    let missing = Mutex::new(Vec::new());
    let result = hash_tree(repo, id, "", &missing)?;

    let mut missing = missing.into_inner().expect("no panics while locked");
    if !missing.is_empty() {
        missing.sort();
        let count = missing.len();
        let mut list: Vec<String> = missing.iter().take(20).map(|m| format!("  {m}")).collect();
        if count > 20 {
            list.push(format!("  ... and {} more", count - 20));
        }
        bail!(
            "{count} submodule(s) are not available, and a tree-sha256 can't be \
             computed, signed or verified without their tree hashes:\n{}\n\
             Check them out with `git submodule update --init --recursive`.",
            list.join("\n")
        );
    }
    Ok(result)
}

enum Kind {
    File,
    Submodule,
}

/// Hash one tree. Submodules that can't be read are pushed onto `missing`
/// (prefixed with `prefix`) instead of failing, so every one gets reported.
fn hash_tree(
    repo: &gix::Repository,
    id: gix::ObjectId,
    prefix: &str,
    missing: &Mutex<Vec<String>>,
) -> Result<([u8; 32], usize)> {
    let tree = repo.find_object(id)?.peel_to_tree()?;

    let mut recorder = gix::traverse::tree::Recorder::default();
    tree.traverse().breadthfirst(&mut recorder)?;

    // Blobs and symlinks have content in this odb, submodule commits are read
    // from the submodule's repository, and trees are already recursed into.
    let mut entries: Vec<(BString, gix::ObjectId, Kind)> = recorder
        .records
        .into_iter()
        .filter_map(|e| match e.mode.kind() {
            EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                Some((e.filepath, e.oid, Kind::File))
            }
            EntryKind::Commit => Some((e.filepath, e.oid, Kind::Submodule)),
            EntryKind::Tree => None,
        })
        .collect();
    entries.sort_unstable_by(|a, b| record_path(a).cmp(&record_path(b)));

    let workdir = repo.workdir().map(Path::to_path_buf);
    let sync_repo = repo.clone().into_sync();
    let hashed = entries
        .par_iter()
        .map_init(
            || (sync_repo.to_thread_local(), Vec::new()),
            |(repo, buf), (path, oid, kind)| -> Result<([u8; 32], usize)> {
                match kind {
                    Kind::File => {
                        let blob = repo.objects.find_blob(oid, buf).map_err(|e| {
                            anyhow::anyhow!("reading blob {oid} for {prefix}{path}: {e}")
                        })?;
                        Ok((Sha256::digest(blob.data).into(), 1))
                    }
                    Kind::Submodule => {
                        let sub_prefix = format!("{prefix}{path}/");
                        match open_submodule(workdir.as_deref(), path, *oid) {
                            Ok(sub) => hash_tree(&sub, *oid, &sub_prefix, missing),
                            Err(reason) => {
                                missing
                                    .lock()
                                    .expect("no panics while locked")
                                    .push(format!("{prefix}{path} ({reason})"));
                                Ok(([0; 32], 0))
                            }
                        }
                    }
                }
            },
        )
        .collect::<Result<Vec<_>>>()?;

    let mut outer = Sha256::new();
    let mut files = 0;
    for (entry, (digest, count)) in entries.iter().zip(&hashed) {
        outer.update(hex_bytes(digest));
        outer.update(b" ");
        outer.update(record_path(entry));
        outer.update(b"\0");
        files += count;
    }
    Ok((outer.finalize().into(), files))
}

/// The path as it appears in the hashed list: submodules get a trailing `/`.
fn record_path((path, _, kind): &(BString, gix::ObjectId, Kind)) -> BString {
    let mut p = path.clone();
    if let Kind::Submodule = kind {
        p.push(b'/');
    }
    p
}

/// Open the checked-out submodule at `path` and make sure it has `commit`.
fn open_submodule(
    workdir: Option<&Path>,
    path: &BString,
    commit: gix::ObjectId,
) -> std::result::Result<gix::Repository, String> {
    let workdir = workdir.ok_or("superproject has no working tree")?;
    let dir: PathBuf = workdir.join(gix::path::from_bstr(path.as_bstr()));
    if !dir.join(".git").exists() {
        return Err("not checked out".into());
    }
    let sub = gix::open(&dir).map_err(|e| format!("can't open: {e}"))?;
    if !sub.has_object(commit) {
        return Err(format!("checked out, but commit {commit} is missing"));
    }
    Ok(sub)
}

pub fn hex(bytes: &[u8; 32]) -> String {
    String::from_utf8(hex_bytes(bytes).to_vec()).expect("hex is ascii")
}

fn hex_bytes(bytes: &[u8; 32]) -> [u8; 64] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = DIGITS[usize::from(b >> 4)];
        out[2 * i + 1] = DIGITS[usize::from(b & 0xf)];
    }
    out
}

/// Parse `--repo <path>` / `-C <path>` plus positional arguments, handing any
/// other `-`/`--` flag to `flag` (which may consume a value from the iterator).
pub fn parse_args(
    usage: &str,
    mut flag: impl FnMut(&str, &mut dyn Iterator<Item = String>) -> Result<bool>,
) -> Result<(String, Vec<String>)> {
    let mut repo_path = String::from(".");
    let mut positional = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--repo" | "-C" => repo_path = args.next().context("--repo needs a path")?,
            "-h" | "--help" => {
                println!("usage: {usage}");
                std::process::exit(0);
            }
            _ if arg.starts_with('-') => {
                if !flag(&arg, &mut args)? {
                    anyhow::bail!("unknown option: {arg}\nusage: {usage}");
                }
            }
            _ => positional.push(arg),
        }
    }
    Ok((repo_path, positional))
}
