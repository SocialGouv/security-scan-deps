# security-scan-deps

Scan a **GitHub organization**, a **GitLab instance/group**, a single repo, or a
local directory for dependencies that appear in one or more vulnerable package
lists (e.g. DataDog/Tenable Shai‑Hulud IOC list, CERT-FR advisories, SafeDep
campaigns, or your own CSV/Markdown file).

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
- Walks Git/GitLab trees recursively, so **monorepos are covered** wherever
  lockfiles live in the project layout.
- Discovery prioritizes the most recently active repos/projects first
  (`pushed_at` for GitHub, `last_activity_at` for GitLab).
- For each lockfile, checks dependency **name + version** against the vulnerable list
  (name-only if `--no-version-check` is enabled).
- Prints any vulnerable packages, grouped per repo (remote mode) or per file (local mode).
  Lockfile **content never appears in stdout/stderr** — only the matches do.

## Requirements

- Node.js **>= 18** (uses native `fetch`)
- For GitHub mode: a token with **read** access on the org’s repositories
  (`GITHUB_TOKEN` env var, `--token-env VAR_NAME`, or `--token VALUE`).
- For GitLab mode: a token with **read_api** scope on the GitLab instance
  (`GITLAB_TOKEN` env var, `--token-env VAR_NAME`, or `--token VALUE`).

## Install

No installation step is required. Just run with Node.js **>= 18**.

## Usage

Main entrypoint: **`index.mjs`**, exposed as `yarn start`.

The platform is selected with `--platform github|gitlab|local`. As a shortcut, a
positional non-flag argument is treated as a GitHub org (e.g.
`node index.mjs SocialGouv`), and `--local` is shorthand for
`--platform local`.

### GitHub (organization / repo) mode

```bash
# with GITHUB_TOKEN from the environment
GITHUB_TOKEN=xxxx yarn start -- <org>

# explicit form
yarn start -- --platform github <org>

# scan a single repo inside the org (SocialGouv/my-repo)
yarn start -- SocialGouv --repo my-repo

# scan via GitHub search only (no Git trees)
yarn start -- SocialGouv --discovery search

# more conservative (ignore versions, match by name only)
yarn start -- SocialGouv --no-version-check

# throttle each API call by 200ms
yarn start -- SocialGouv --delay-ms 200

# override the remote compromised-packages URL
yarn start -- SocialGouv --packages-url https://example.com/custom-list.csv

# use a local compromised-packages list (Markdown or CSV)
yarn start -- SocialGouv --packages-file ./compromised.csv
```

### GitLab (instance / group / project) mode

GitLab is a self-hosted service: you pass the **host** as the target.

```bash
# whole instance — all projects accessible to the token (membership=true)
GITLAB_TOKEN=xxxx yarn start -- --platform gitlab gitlab.example.com

# restrict to a group (subgroups included)
yarn start -- --platform gitlab gitlab.example.com --group my-group

# restrict to a single project (id or "namespace/path")
yarn start -- --platform gitlab gitlab.example.com --project 42
yarn start -- --platform gitlab gitlab.example.com --project ns/path

# read the token from an arbitrary env var (instead of GITLAB_TOKEN)
source .env && \
  yarn start -- --platform gitlab gitlab.example.com \
    --token-env MY_GITLAB_TOKEN_VAR

# privacy-preserving run: suppress per-project progress logs and hash file paths
yarn start -- --platform gitlab gitlab.example.com \
  --findings-only --redact-paths
```

### Local mode (no remote)

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
node index.mjs [--platform github] <org>  [--repo REPO]    [common options]
node index.mjs   --platform gitlab  <host> [--group GROUP | --project PROJECT] [common options]
node index.mjs   --local                                                       [common options]
```

Common options:

- `--token VALUE` / `--token-env VAR_NAME` (or defaults: `GITHUB_TOKEN` /
  `GITLAB_TOKEN`). `--token-env` is preferred when the secret lives in a
  pre-existing variable: nothing is read by the tool from disk, and the value
  never appears on the command line.
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
- `--redact-paths`: replace each file path in the findings output with
  `sha256:<16-hex>` (the repo name is kept). Useful when the report is
  reviewed in a context where source-tree layouts shouldn’t be exposed.
- `--findings-only`: suppress per-repo / per-project progress lines on
  stderr. The final discovered-lockfiles summary and the findings list are
  still printed.
- `--delay-ms MS` (aliases: `--github-delay-ms`, `--gitlab-delay-ms`,
  also `GITHUB_DELAY_MS` env var): artificial throttle in milliseconds
  before each API call. Helps when scanning very large orgs/instances.

GitHub options:

- `--repo REPO`: limit the scan to a single repository within the org
  (`owner/repo` or just `repo`).
- `--discovery MODE`:
  - `trees` (default): walk Git trees of all non‑archived repos (default branch).
  - `search`: use GitHub `/search/code` only.

GitLab options:

- `--group GROUP`: GitLab group id or full path. Subgroups are included.
- `--project PROJECT`: GitLab project id or `namespace/project` path.

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
