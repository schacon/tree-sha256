//! Print the tree-sha256 of a revision.
//!
//! Usage: tree-sha256 [--repo <path>] [<rev>]   (defaults: ".", "HEAD")

use std::time::Instant;

use anyhow::{Context, Result};
use tree_sha256::{hex, parse_args, tree_sha256_rev};

fn main() -> Result<()> {
    let (repo_path, positional) =
        parse_args("tree-sha256 [--repo <path>] [<rev>]", |_, _| Ok(false))?;
    let rev = positional.first().map_or("HEAD", String::as_str);

    let repo = gix::open(&repo_path).with_context(|| format!("opening {repo_path}"))?;

    let start = Instant::now();
    let (digest, files) = tree_sha256_rev(&repo, rev)?;
    let elapsed = start.elapsed();

    println!("{}", hex(&digest));
    eprintln!("{files} files hashed in {elapsed:.2?}");
    Ok(())
}
