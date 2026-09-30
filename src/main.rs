//! Print the tree-sha256 of a revision.
//!
//! Usage: tree-sha256 [--repo <path>] [--exclude-submodule <pattern>]...
//!                    [--exclude-from <file>] [<rev>]

use std::time::Instant;

use anyhow::{Context, Result};
use tree_sha256::{Options, hex, parse_args, tree_sha256_rev};

const USAGE: &str = "tree-sha256 [--repo <path>] [--exclude-submodule <pattern>]... \
                     [--exclude-from <file>] [<rev>]";

fn main() -> Result<()> {
    let mut opts = Options::default();
    let (repo_path, positional) = parse_args(USAGE, |flag, args| opts.flag(flag, args))?;
    let rev = positional.first().map_or("HEAD", String::as_str);

    let repo = gix::open(&repo_path).with_context(|| format!("opening {repo_path}"))?;

    let start = Instant::now();
    let hashed = tree_sha256_rev(&repo, rev, &opts)?;
    let elapsed = start.elapsed();

    println!("{}", hex(&hashed.digest));
    eprintln!(
        "{} files in {} submodules hashed in {elapsed:.2?}",
        hashed.files, hashed.submodules
    );
    report_skipped(&hashed);
    Ok(())
}

fn report_skipped(hashed: &tree_sha256::Hashed) {
    if !hashed.excluded.is_empty() {
        eprintln!("{} submodules excluded (not hashed):", hashed.excluded.len());
        for (path, commit) in &hashed.excluded {
            eprintln!("  {path} ({commit})");
        }
    }
    if !hashed.cycles.is_empty() {
        eprintln!("{} submodules recorded as cycles:", hashed.cycles.len());
        for path in &hashed.cycles {
            eprintln!("  {path}");
        }
    }
}
