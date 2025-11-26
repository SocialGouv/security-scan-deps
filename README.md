# security-scan-deps

Scan a GitHub organization for dependencies compromised in the
[Tenable Shai‑Hulud / "Second Coming"](https://github.com/tenable/shai-hulud-second-coming-affected-packages) incident.

## What it does

- Loads the latest `list.md` from Tenable (or a custom URL).
- Scans all repos in a GitHub org for:
  - `yarn.lock` (Yarn v1 / v2+ / Berry)
  - `package-lock.json` (npm v1–v3)
  - `pnpm-lock.yaml` (pnpm)
- Checks each dependency name/version against Tenable’s list.
- Prints any compromised packages per repo.

## Requirements

- Node.js **>= 18** (uses native `fetch`)
- GitHub token with **read** access on the org’s repositories, provided via the
  `GITHUB_TOKEN` environment variable or `--token` CLI option.

## Install

No installation step is required. Just run with Node.js **>= 18**.

## Usage

Main entrypoint: **`index.mjs`**, exposed as `yarn start`.

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

# scan via GitHub search only
yarn start -- SocialGouv --discovery search

# more conservative (ignore versions, match by name only)
yarn start -- SocialGouv --no-version-check
```

### CLI options

```text
node index.mjs <org> [--token TOKEN] [--no-version-check] [--packages-url URL] [--discovery trees|search]
```

- `<org>` (required): GitHub organization name
- `--token TOKEN`: GitHub token (if not using `GITHUB_TOKEN` env var)
- `--no-version-check`: match by package **name only** (more noisy, safer)
- `--packages-url URL`: override Tenable `list.md` URL
- `--discovery MODE`:
  - `trees` (default): walk Git trees of all non‑archived repos (default branch)
  - `search`: use GitHub `/search/code` only

## Output

Summary of discovered lockfiles, then (if any) compromised packages, e.g.:

```text
Lockfiles discovered:
  yarn.lock         : 145
  package-lock.json : 34
  pnpm-lock.yaml    : 12

Compromised packages detected:
- SocialGouv/xxx :: yarn.lock (yarn.lock)
    • ngx-bootstrap@19.0.3
```

If nothing is found:

```text
No Shai-Hulud compromised packages found in yarn.lock / package-lock.json / pnpm-lock.yaml in the organization.
```
