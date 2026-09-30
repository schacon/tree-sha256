# tree-sha256

A SHA-256 content hash for a Git commit's tree, and SSH-signed tags that carry it.

Git names objects by SHA-1. A signed tag signs a SHA-1 commit id, so its
guarantee about the files underneath rests on SHA-1. `tree-sha256` hashes the
actual file contents from the object database with SHA-256 instead, including
the contents of submodules. `tree-sha256-tag` puts that hash in a header of a
signed tag, so the signature covers the content directly.

## Tools

| Binary | What it does |
|---|---|
| `tree-sha256` | Prints the tree-sha256 of a revision. |
| `tree-sha256-tag` | Creates an SSH-signed annotated tag with a `tree-sha256` header. |
| `tree-sha256-verify` | Checks the tag's signature and recomputes the hash. |

## Install

```sh
cargo install --path .
```

## Usage

```sh
# Print the hash of HEAD (or any revision)
tree-sha256 [--repo <path>] [<rev>]

# Create a signed tag for a commit
tree-sha256-tag [--repo <path>] [-m <message>] [-f] <tagname> [<rev>]

# Verify it
tree-sha256-verify [--repo <path>] [--no-signature] <tag>
```

All three accept `--exclude-submodule <pattern>` (repeatable) and
`--exclude-from <file>` (one pattern per line, `#` comments allowed); see
[Submodules](#submodules). `tree-sha256-verify` ignores these flags and uses
the exclusions recorded in the tag instead.

Example:

```console
$ tree-sha256-tag -m "Release 1.0" v1.0
2f1c…  (tag object id)
tagged 78bd4582… as v1.0 (tree-sha256 775aff90…3d89)
4880 files in 1 submodules hashed in 21.49ms, signed in 7.74ms, written in 934.62µs, total 31.29ms

$ tree-sha256-verify v1.0
Good "git" signature for you@example.com with ED25519 key SHA256:…
4880 files in 1 submodules hashed in 18.15ms, total 24.44ms
OK v1.0 78bd4582… tree-sha256 775aff90…3d89
```

`tree-sha256-verify` exits 0 when the signature is good and the hash matches,
and 1 otherwise.

### Signing setup

Signing uses SSH, configured the same way as `git tag -s` with
`gpg.format=ssh`:

```sh
git config user.signingKey ~/.ssh/id_ed25519.pub     # a key file, or "key::ssh-ed25519 AAAA…" to sign via ssh-agent
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers   # trusted keys, for verification
```

`gpg.ssh.program` is honored if set. Verification runs `git verify-tag`, so the
allowed-signers file decides which keys are trusted.

## The tag

```text
object 78bd45828aa36fbde3161f49da15272dff3d06f5
type commit
tag v1.0
tagger Scott Chacon <schacon@gmail.com> 1790749714 +0200
tree-sha256-excluded ios/third_party/webkit/src     (only if submodules were excluded)
tree-sha256 775aff90d07c9a73f19ef83ab89bd8e95d1d835325d53cc57a2232b015783d89

Release 1.0
-----BEGIN SSH SIGNATURE-----
…
-----END SSH SIGNATURE-----
```

The extra headers come after `tagger`, so they are part of the signed payload:
changing them invalidates the signature. Git ignores unknown tag headers by
default (`git fsck --strict` does not complain), and `git verify-tag` accepts
the tag as usual.

## The hash

Every entry in the commit's tree, recursively, becomes one record. Records
are sorted by record path (byte order), and the tree-sha256 is SHA-256 over
their concatenation:

```text
<hex sha256 of file content> SP <path> NUL
<hex tree-sha256 of submodule> SP <path> / NUL
cycle:<commit id> SP <path> / NUL
excluded:<commit id> SP <path> / NUL
```

- Files are regular files, executables and symlinks (a symlink's target text is
  hashed). The file mode is not part of the hash.
- Paths are full paths from the root of the tree being hashed.
- Tree paths never contain NUL or end in `/`, and `cycle:`/`excluded:` can't be
  hex, so the list is unambiguous.

This can be reproduced with plain git: hash each blob from
`git ls-tree -r -z <rev>` with `sha256sum`, build the records above, sort them
and hash the result.

## Submodules

Each submodule's tree is hashed from the submodule's own repository at the
commit the parent pins, recursively, and its tree-sha256 becomes one record in
the parent's list.

- **Not checked out:** the tools refuse to run, listing every submodule that is
  missing. A tag can't be signed or verified without the submodule hashes.
- **Cycles:** if a submodule pins a commit that is already being hashed further
  up the same chain, it's recorded as `cycle:<commit id>` instead of being
  followed again.
- **Excluded:** `--exclude-submodule <pattern>` leaves out submodules whose
  full path matches a glob (`*` matches any characters including `/`, `?` one
  character). An excluded submodule is recorded as `excluded:<commit id>`, so
  its pinned commit is still covered but its contents are not. The tag lists
  each excluded path in a `tree-sha256-excluded` header, and
  `tree-sha256-verify` reports them as **not verifiable**:

```console
$ tree-sha256-tag --exclude-submodule 'sha1collisiondetection' v1.0
…
1 submodules excluded and recorded as unverifiable in tree-sha256-excluded headers

$ tree-sha256-verify v1.0
…
NOT VERIFIABLE: 1 submodules were excluded when signing; only their pinned commits are covered, not their contents:
  sha1collisiondetection (855827c583bc30645ba427885caa40c5b81764d2)
OK v1.0 78bd4582… tree-sha256 6c0f70f9… (1 submodules not verifiable)
```

## Performance

Blobs are read and hashed in parallel (rayon, one repository handle per
thread). Measured on an 18-core Apple Silicon Mac with the packs in the OS cache,
top-level repository only:

| Repository | Files | Content | `tree-sha256-tag` | `tree-sha256-verify` | 1 thread |
|---|---|---|---|---|---|
| git.git | 4,862 | 48 MiB | 25 ms | 25 ms | 117 ms |
| linux | 96,045 | 1.5 GiB | 229 ms | 228 ms | 2.2 s |
| chromium (shallow) | 508,167 | 4.1 GiB | 750 ms | 755 ms | 7.9 s |

The time is almost all hashing: SSH signing adds about 5–8 ms and writing the
tag under 1 ms. Verification checks the signature in parallel with hashing.

## Building

Rust 2024 edition. Object access uses [gitoxide](https://github.com/GitoxideLabs/gitoxide)
(`gix`); signing and signature verification shell out to `ssh-keygen` and
`git verify-tag`.

```sh
cargo build --release
cargo test
```
