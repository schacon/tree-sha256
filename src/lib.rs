//! SHA-256 digest over every blob in a tree, including checked-out submodules.
//!
//! Each blob's content is read from the object database and hashed with
//! SHA-256. Each submodule's committed tree is hashed the same way, recursively,
//! from the submodule's own repository. The final hash is SHA-256 over one
//! record per entry, ordered by record path (byte order):
//!
//! ```text
//! <hex sha256 of file content> SP <path> NUL
//! <hex tree-sha256 of submodule> SP <path> / NUL
//! cycle:<commit id> SP <path> / NUL       (commit already being hashed above)
//! excluded:<commit id> SP <path> / NUL    (matched an exclude pattern)
//! ```
//!
//! Tree paths never end in `/` and never contain NUL, and `cycle:`/`excluded:`
//! can't be hex, so the list is unambiguous. Recording the pinned commit id for
//! cycles and exclusions means changing what they point at still changes the hash.

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
/// Tag header naming one submodule (full path) that was left out of the digest
/// and therefore can't be verified.
pub const EXCLUDED_HEADER: &str = "tree-sha256-excluded";

/// Submodules left out of the hash: glob patterns over the full path from the
/// top repository (`*` also matches `/`, `?` matches one character), and exact
/// paths (as read back from a tag's `tree-sha256-excluded` headers).
#[derive(Default, Clone)]
pub struct Options {
    pub exclude: Vec<String>,
    pub exact: Vec<String>,
}

impl Options {
    /// Handle `--exclude-submodule <pattern>` and `--exclude-from <file>`.
    pub fn flag(&mut self, flag: &str, args: &mut dyn Iterator<Item = String>) -> Result<bool> {
        match flag {
            "--exclude-submodule" => {
                let pattern = args.next().context("--exclude-submodule needs a pattern")?;
                self.add(pattern)?;
            }
            "--exclude-from" => {
                let file = args.next().context("--exclude-from needs a file")?;
                let text = std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?;
                for line in text.lines().map(str::trim) {
                    if !line.is_empty() && !line.starts_with('#') {
                        self.add(line.to_owned())?;
                    }
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn add(&mut self, pattern: String) -> Result<()> {
        let pattern = pattern.trim_end_matches('/').to_owned();
        if pattern.is_empty() || pattern.contains(['\n', '\0']) {
            bail!("invalid exclude pattern {pattern:?}");
        }
        if !self.exclude.contains(&pattern) {
            self.exclude.push(pattern);
        }
        Ok(())
    }

    fn excludes(&self, path: &[u8]) -> bool {
        self.exact.iter().any(|p| p.as_bytes() == path)
            || self.exclude.iter().any(|p| glob_match(p.as_bytes(), path))
    }
}

/// The result of hashing a tree.
pub struct Hashed {
    pub digest: [u8; 32],
    /// Files whose content was hashed, across all submodules.
    pub files: usize,
    /// Submodules whose trees were hashed.
    pub submodules: usize,
    /// Submodules left out because they were excluded: (full path, pinned commit).
    pub excluded: Vec<(String, gix::ObjectId)>,
    /// Full paths of submodules whose commit was already being hashed above them.
    pub cycles: Vec<String>,
}

/// Resolve `rev` and hash the tree it points to. Tags and commits are peeled.
pub fn tree_sha256_rev(repo: &gix::Repository, rev: &str, opts: &Options) -> Result<Hashed> {
    let id = repo
        .rev_parse_single(rev)
        .with_context(|| format!("resolving {rev}"))?;
    tree_sha256(repo, id.detach(), opts)
}

/// Hash every blob in the tree reachable from `id` (a tree, commit or tag),
/// recursing into submodules. Fails if any submodule that isn't excluded isn't
/// checked out, listing all of them.
pub fn tree_sha256(repo: &gix::Repository, id: gix::ObjectId, opts: &Options) -> Result<Hashed> {
    let walk = Walk {
        opts,
        missing: Mutex::default(),
        excluded: Mutex::default(),
        cycles: Mutex::default(),
    };
    let top = repo.find_object(id)?.peel_to_commit().ok().map(|c| c.id);
    let (digest, files, submodules) = hash_tree(repo, id, "", &top.into_iter().collect::<Vec<_>>(), &walk)?;

    let mut missing = walk.missing.into_inner().expect("no panics while locked");
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
             Check them out with `git submodule update --init --recursive`, or leave \
             them out explicitly with --exclude-submodule <pattern>.",
            list.join("\n")
        );
    }
    let mut excluded = walk.excluded.into_inner().expect("no panics while locked");
    let mut cycles = walk.cycles.into_inner().expect("no panics while locked");
    excluded.sort();
    cycles.sort();
    Ok(Hashed { digest, files, submodules, excluded, cycles })
}

struct Walk<'a> {
    opts: &'a Options,
    missing: Mutex<Vec<String>>,
    excluded: Mutex<Vec<(String, gix::ObjectId)>>,
    cycles: Mutex<Vec<String>>,
}

enum Kind {
    File,
    Submodule,
}

enum Value {
    Digest([u8; 32]),
    Cycle(gix::ObjectId),
    Excluded(gix::ObjectId),
}

/// Hash one tree. `chain` holds the commits of the submodules being hashed
/// above this one. Submodules that can't be read are recorded in `walk.missing`
/// instead of failing, so every one gets reported.
fn hash_tree(
    repo: &gix::Repository,
    id: gix::ObjectId,
    prefix: &str,
    chain: &[gix::ObjectId],
    walk: &Walk<'_>,
) -> Result<([u8; 32], usize, usize)> {
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
            |(repo, buf), (path, oid, kind)| -> Result<(Value, usize, usize)> {
                let full = format!("{prefix}{path}");
                match kind {
                    Kind::File => {
                        let blob = repo.objects.find_blob(oid, buf).map_err(|e| {
                            anyhow::anyhow!("reading blob {oid} for {full}: {e}")
                        })?;
                        Ok((Value::Digest(Sha256::digest(blob.data).into()), 1, 0))
                    }
                    Kind::Submodule if walk.opts.excludes(full.as_bytes()) => {
                        walk.excluded.lock().expect("no panics while locked").push((full, *oid));
                        Ok((Value::Excluded(*oid), 0, 0))
                    }
                    Kind::Submodule if chain.contains(oid) => {
                        walk.cycles.lock().expect("no panics while locked").push(full);
                        Ok((Value::Cycle(*oid), 0, 0))
                    }
                    Kind::Submodule => match open_submodule(workdir.as_deref(), path, *oid) {
                        Ok(sub) => {
                            let mut sub_chain = chain.to_vec();
                            sub_chain.push(*oid);
                            let (digest, files, subs) =
                                hash_tree(&sub, *oid, &format!("{full}/"), &sub_chain, walk)?;
                            Ok((Value::Digest(digest), files, subs + 1))
                        }
                        Err(reason) => {
                            walk.missing
                                .lock()
                                .expect("no panics while locked")
                                .push(format!("{full} ({reason})"));
                            Ok((Value::Digest([0; 32]), 0, 0))
                        }
                    },
                }
            },
        )
        .collect::<Result<Vec<_>>>()?;

    let mut outer = Sha256::new();
    let (mut files, mut submodules) = (0, 0);
    for (entry, (value, f, s)) in entries.iter().zip(&hashed) {
        match value {
            Value::Digest(d) => outer.update(hex_bytes(d)),
            Value::Cycle(oid) => outer.update(format!("cycle:{oid}")),
            Value::Excluded(oid) => outer.update(format!("excluded:{oid}")),
        }
        outer.update(b" ");
        outer.update(record_path(entry));
        outer.update(b"\0");
        files += f;
        submodules += s;
    }
    Ok((outer.finalize().into(), files, submodules))
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

/// Glob match where `*` matches any run of bytes (including `/`) and `?` one byte.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut backtrack = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                backtrack = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match backtrack {
                Some((bp, bt)) => {
                    p = bp + 1;
                    t = bt + 1;
                    backtrack = Some((bp, bt + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn globs() {
        assert!(glob_match(b"a/b", b"a/b"));
        assert!(!glob_match(b"a/b", b"a/bc"));
        assert!(glob_match(b"*/gles1_conform", b"third_party/angle/third_party/gles1_conform"));
        assert!(glob_match(b"ios/*/src", b"ios/third_party/webkit/src"));
        assert!(glob_match(b"*internal*", b"chrome/browser/internal"));
        assert!(!glob_match(b"*internal", b"internal/x"));
        assert!(glob_match(b"a?c", b"abc"));
        assert!(glob_match(b"*", b""));
    }
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
