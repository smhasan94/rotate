# Releasing rotate

A release is a `v<version>` tag on `main`. `.github/workflows/release.yml`
builds, publishes and checks it, and updates the Homebrew tap. Nothing is
published to crates.io (the name `rotate` is taken there).

## Steps

1. In one pull request (`chore(release): vX.Y.Z`): set `version` in
   `Cargo.toml` (and `Cargo.lock`), add the `## [X.Y.Z] - <date>` section
   and its link to `CHANGELOG.md`, set `VERSION=X.Y.Z` in the README
   install block and the `--tag vX.Y.Z` in `docs/usage.md`.
   `tests/user_docs.rs` fails until all of them name the new version.
2. Merge it, then tag the merge commit and push the tag:

   ```sh
   git switch main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

3. Watch the `release` run. When it is green, the release is published,
   verified and in the Homebrew tap.

## What the release workflow does

| Job | What it does |
| --- | --- |
| `version check` | Fails unless the tag is `v` plus the `Cargo.toml` version. |
| `build` | Builds and smoke-tests `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` and `aarch64-apple-darwin`, and packs `rotate-<version>-<target>.tar.gz`. |
| `checksums` | Writes `SHA256SUMS` for the four tarballs. |
| `release notes` | Takes the `CHANGELOG.md` section as the notes and checks the README install block names the version. |
| `publish` | Creates the GitHub Release with the four tarballs and `SHA256SUMS`. The only job with write access to this repository. |
| `verify release` | Downloads the published assets on Linux and macOS, checks every checksum, `rotate --version` and a `rotate plan` smoke run. |
| `README install` | Runs the README install block on Debian and macOS. |
| `homebrew tap` | Updates `Formula/rotate.rb` in the tap (below). |
| `brew install` | Runs `brew install smhasan94/rotate/rotate` on macOS, checks `rotate --version` prints the new version and runs `brew test`. |

A pull request that changes the workflow or `scripts/` runs everything up
to `release notes` and publishes nothing.

## Homebrew tap

The formula lives in
[smhasan94/homebrew-rotate](https://github.com/smhasan94/homebrew-rotate)
as `Formula/rotate.rb`. It is generated, never edited by hand: the template
is `packaging/homebrew/rotate.rb.tmpl` in this repository and
`scripts/render-formula.sh` fills in the version and the four checksums:

```sh
scripts/render-formula.sh X.Y.Z SHA256SUMS > rotate.rb
```

The script fails, naming each missing target, unless `SHA256SUMS` has one
well-formed line for every release tarball of that version.

After `verify release` passes, the `homebrew tap` job:

1. downloads `SHA256SUMS` from the published release and renders the
   formula;
2. runs `brew audit --strict --online` and `brew style` on it in a
   throwaway local tap;
3. checks out the tap with the `HOMEBREW_TAP_TOKEN` secret, writes
   `Formula/rotate.rb` and pushes one commit, `rotate X.Y.Z`, to its default
   branch. If the tap already has that exact formula (a re-run), it commits
   nothing.

Then `brew install` installs from the tap as a user would.

Pull requests that change `packaging/` or the render script run
`.github/workflows/homebrew.yml`, which renders the fixture in
`packaging/homebrew/fixtures/` and runs the same audit and style checks.
`tests/homebrew.rs` checks the render script itself in `cargo test`.

### The tap token (one-time setup)

1. On GitHub: Settings, Developer settings, Personal access tokens,
   Fine-grained tokens, Generate new token. Resource owner `smhasan94`;
   repository access "Only select repositories" with
   `smhasan94/homebrew-rotate` only; repository permissions: Contents
   "Read and write" (Metadata "Read-only" is added automatically). Give it
   an expiry and note the date.
2. Store it as an Actions secret of this repository:

   ```sh
   gh secret set HOMEBREW_TAP_TOKEN -R smhasan94/rotate
   ```

   (`gh` reads the value from a hidden prompt.)
3. Before it expires, generate a new one the same way and set the secret
   again.

Without the secret, the `homebrew tap` job prints the notice "Homebrew tap
not updated" and skips its other steps, `brew install` is skipped, and the
release still succeeds. To catch up afterwards, add the secret and re-run
the `homebrew tap` job of that release run, or render the formula locally
from the release's `SHA256SUMS` and commit it to the tap:

```sh
gh release download vX.Y.Z -p SHA256SUMS -R smhasan94/rotate -D /tmp/rotate-X.Y.Z
scripts/render-formula.sh X.Y.Z /tmp/rotate-X.Y.Z/SHA256SUMS > rotate.rb
```

The token can write to the tap and nothing else. The job hands it only to
the checkout of the tap and never prints it.
