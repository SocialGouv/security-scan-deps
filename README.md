# security-scan-deps

Scan a GitHub organization (or a single repo, or a local directory) for dependencies that appear in one or more
vulnerable package lists (for example the DataDog/Tenable Shai‑Hulud IOC list,
CERT-FR advisories, or your own CSV/Markdown file).

## What it does

- Loads a list of vulnerable npm packages from:
  - DataDog’s consolidated Shai‑Hulud CSV (by default), and
  - Tenable’s legacy Markdown list (`list.md`),
  - optionally a custom URL or local file.
- Merges these sources into a single map of vulnerable packages / versions.
- Scans for lockfiles:
  - `yarn.lock` (Yarn v1 / v2+ / Berry)
  - `package-lock.json` (npm v1–v3)
  - `pnpm-lock.yaml` (pnpm)
  - `bun.lock` (Bun)
- For each lockfile, checks dependency **name + version** against the vulnerable list
  (name-only if `--no-version-check` is enabled).
- Prints any vulnerable packages, grouped per repo (GitHub mode) or per file (local mode).

## Requirements

- Node.js **>= 18** (uses native `fetch`)
- For GitHub mode:
  - A GitHub token with **read** access on the org’s repositories, provided via the
    `GITHUB_TOKEN` environment variable or `--token` CLI option.

## Install

No installation step is required. Just run with Node.js **>= 18**.

## Usage

Main entrypoint: **`index.mjs`**, exposed as `yarn start`.

### GitHub (organization / repo) mode

```bash
# with GITHUB_TOKEN from the environment
GITHUB_TOKEN=xxxx yarn start -- <org>

# pure node
GITHUB_TOKEN=xxxx node index.mjs <org>
```

Examples:

```bash
# scan org "SocialGouv" using Git trees (default, exhaustive)
yarn start -- SocialGouv

# scan a single repo inside the org (SocialGouv/my-repo)
yarn start -- SocialGouv --repo my-repo

# scan via GitHub search only (no Git trees)
yarn start -- SocialGouv --discovery search

# more conservative (ignore versions, match by name only)
yarn start -- SocialGouv --no-version-check

# add a small delay between GitHub API calls (in milliseconds)
GITHUB_DELAY_MS=200 yarn start -- SocialGouv

# or via CLI flag
yarn start -- SocialGouv --github-delay-ms 200

# override the remote compromised-packages URL
yarn start -- SocialGouv --packages-url https://example.com/custom-list.csv

# use a local compromised-packages list (Markdown or CSV)
yarn start -- SocialGouv --packages-file ./compromised.csv
```

### Local mode (no GitHub)

Scan the **current working directory** for lockfiles and check them against the compromised list:

```bash
# via yarn
yarn start -- --local

# pure node
node index.mjs --local

# local scan with name-only matching (ignore versions)
node index.mjs --local --no-version-check

# local scan with a custom list file
node index.mjs --local --packages-file ./compromised.md
```

### CLI options

Raw CLI usage (matches the script’s built‑in help):

```text
Usage: node index.mjs <org> [--repo REPO] [--token TOKEN] [--no-version-check] [--packages-url URL] [--packages-file PATH] [--discovery MODE] [--github-delay-ms MS]
   or: node index.mjs --local [--no-version-check] [--packages-url URL] [--packages-file PATH]
```

Options:

- `<org>` (required in GitHub mode): GitHub organization name
- `--repo REPO`: limit the scan to a single repository within the org.
  - You can pass either `owner/repo` or just `repo` (in which case `owner` is `<org>`).
- `--token TOKEN`: GitHub token (if not using the `GITHUB_TOKEN` env var).
- `--no-version-check`: match by package **name only** (more noisy, but conservative).
  When version checking is enabled (default), the tool supports:
  - exact versions: `1.2.3`
  - wildcard versions with `x`: `15.0.x`, `15.x`
  - simple range expressions using `>=`, `>`, `<`, `<=`, `=`
    (e.g. `">=15.0.0 <15.0.5"`).
- `--packages-url URL`: override the default remote package list URL.
  - If you override this, **only that URL** is used (no DataDog+Tenable aggregation).
- `--packages-file PATH`: load the compromised package list from a local file
  (Markdown or CSV). This bypasses remote fetching.
- `--discovery MODE` (GitHub mode only):
  - `trees` (default): walk Git trees of all non‑archived repos (default branch).
  - `search`: use GitHub `/search/code` only.
- `--github-delay-ms MS`: add an artificial delay (in milliseconds) before each
  GitHub API call. You can also set `GITHUB_DELAY_MS` in the environment.
  This helps reduce the chance of hitting GitHub’s rate limits on very large orgs.

## Output

First, the tool prints a summary of discovered lockfiles (GitHub mode):

```text
Lockfiles discovered:
  yarn.lock         : 145
  package-lock.json : 34
  pnpm-lock.yaml    : 12
  bun.lock          : 3
```

If any compromised dependencies are found, they are printed by repo and file:

```text
Compromised packages detected:
==============================
- SocialGouv/xxx :: yarn.lock (yarn.lock)
    • ngx-bootstrap@19.0.3
```

If nothing is found, you’ll see:

```text
No vulnerable dependencies found in yarn.lock / package-lock.json / pnpm-lock.yaml / bun.lock in the scanned scope.
```
