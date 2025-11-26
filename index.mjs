#!/usr/bin/env node
/* index.mjs
 *
 * Scan a GitHub organization for Shai‑Hulud ("Second Coming") compromised
 * packages in yarn.lock / package-lock.json / pnpm-lock.yaml.
 *
 * Requirements:
 *   - Node.js >= 18 (for native fetch)
 *   - A GitHub token with read access to the org's repositories
 *     (GITHUB_TOKEN env var or --token).
 */

import dotenv from "dotenv";

dotenv.config();

const GITHUB_API_URL = "https://api.github.com";

// Default URL to Tenable's list.md (raw)
const DEFAULT_PACKAGE_LIST_URL =
  "https://github.com/tenable/shai-hulud-second-coming-affected-packages/raw/main/list.md";

/**
 * CLI args parsing.
 * Usage: node index.mjs <org> [--token TOKEN] [--no-version-check] [--packages-url URL] [--discovery MODE]
 */
function parseArgs() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0].startsWith("-")) {
    console.error(
      "Usage: node index.mjs <org> [--token TOKEN] [--no-version-check] [--packages-url URL] [--discovery MODE]"
    );
    process.exit(1);
  }

  const org = argv[0];
  let token = process.env.GITHUB_TOKEN || null;
  let noVersionCheck = false;
  let packagesUrl = DEFAULT_PACKAGE_LIST_URL;
  let discoveryMode = "trees"; // "trees" (default) or "search"

  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--token" && argv[i + 1]) {
      token = argv[++i];
    } else if (arg === "--no-version-check") {
      noVersionCheck = true;
    } else if (arg === "--packages-url" && argv[i + 1]) {
      packagesUrl = argv[++i];
    } else if (arg === "--discovery" && argv[i + 1]) {
      discoveryMode = argv[++i];
    }
  }

  if (!token) {
    console.error(
      "Error: no GitHub token provided. Use --token or the GITHUB_TOKEN environment variable."
    );
    process.exit(1);
  }

  return { org, token, noVersionCheck, packagesUrl, discoveryMode };
}

/**
 * Build common GitHub API headers.
 */
function buildGithubHeaders(token) {
  return {
    "User-Agent": "shai-hulud-org-scanner",
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
  };
}

/**
 * Load compromised packages from Tenable's Markdown (list.md).
 *
 * Returns Map<string, Set<string>> where:
 *   - key    : npm package name (e.g. "@scope/pkg" or "lodash")
 *   - values : set of malicious versions (empty Set => all versions)
 */
async function loadCompromisedPackagesFromMarkdown(url) {
  // If the URL is a blob URL, convert it to raw
  let fetchUrl = url.replace("/blob/", "/raw/");

  console.error(`Loading compromised package list from ${fetchUrl}...`);
  const res = await fetch(fetchUrl);
  if (!res.ok) {
    throw new Error(
      `Failed to download package list (${res.status} ${res.statusText})`
    );
  }
  const text = await res.text();

  const compromised = new Map();
  const lines = text.split(/\r?\n/);

  // 1) Try to parse the current Markdown table format
  //    | Package Name | Vulnerable Versions |
  const tableLines = lines.filter((l) => l.trim().startsWith("|"));
  if (tableLines.length >= 3) {
    // Skip header and separator
    for (const line of tableLines.slice(2)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed === "|" || /^\|\s*:?[-]+/.test(trimmed)) continue;

      // Example: "| @scope/pkg | 1.2.3, 1.2.4 |"
      const cells = trimmed
        .split("|")
        .map((c) => c.trim())
        .filter(Boolean);

      if (cells.length < 2) continue;

      const name = cells[0];
      const versionsCell = cells[1] || "";
      if (!name) continue;

      if (!compromised.has(name)) {
        compromised.set(name, new Set());
      }
      const versionsSet = compromised.get(name);

      const vTrimmed = versionsCell.trim();
      if (!vTrimmed || vTrimmed === "-") {
        // No version specified => all versions considered compromised
        // Convention: empty Set => all versions
      } else {
        for (const part of vTrimmed.split(",")) {
          const v = part.trim();
          if (v) versionsSet.add(v);
        }
      }
    }
  }

  // 2) Fallback: older "name@version" free-text format
  if (compromised.size === 0) {
    const pkgRegex =
      /(@[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+)@([0-9][0-9A-Za-z.+-]*)/g;

    for (const line of lines) {
      let match;
      while ((match = pkgRegex.exec(line)) !== null) {
        const name = match[1].trim();
        const version = match[2].trim();
        if (!compromised.has(name)) {
          compromised.set(name, new Set());
        }
        compromised.get(name).add(version);
      }
    }
  }

  console.error(`  -> ${compromised.size} compromised packages parsed from markdown.`);

  if (compromised.size === 0) {
    console.error(
      "Warning: no entries found in list.md. The format may have changed, or the regex is too strict."
    );
  }

  return compromised;
}

/**
 * Build a matcher function: (name, version) => boolean
 *  - noVersionCheck = true => match by name only
 *  - otherwise, check known vulnerable versions
 */
function buildMatcher(compromisedMap, noVersionCheck) {
  return (name, version) => {
    if (!name) return false;
    const versions = compromisedMap.get(name);
    if (!versions) return false;

    if (noVersionCheck) return true;

    if (versions.size === 0) {
      // No versions specified: all versions are considered compromised
      return true;
    }

    if (!version) {
      // Cannot determine version: treat as compromised (conservative)
      return true;
    }

    return versions.has(version);
  };
}

/**
 * Search all files with a given filename in an org using /search/code.
 * Limited to 1000 results by GitHub.
 */
async function searchLockFiles(org, filename, headers) {
  const perPage = 100;
  let page = 1;
  let allItems = [];

  while (true) {
    const q = `filename:${filename} org:${org}`;
    const params = new URLSearchParams({
      q,
      per_page: String(perPage),
      page: String(page),
    });

    const url = `${GITHUB_API_URL}/search/code?${params.toString()}`;
    console.error(`GitHub search: ${filename} (page ${page})...`);
    const res = await fetch(url, { headers });

    if (res.status === 403) {
      const body = await res.text();
      if (body.toLowerCase().includes("rate limit")) {
        console.error("GitHub rate limit reached (403). Stopping search.");
        break;
      } else {
        throw new Error(`403 error on /search/code: ${body}`);
      }
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(
        `Error calling /search/code (${res.status} ${res.statusText}): ${body}`
      );
    }

    const data = await res.json();
    const items = data.items || [];
    allItems = allItems.concat(items);

    if (items.length < perPage || page * perPage >= 1000) {
      break;
    }
    page += 1;
  }

  return allItems;
}

/**
 * Search lockfiles in a specific repo via /search/code.
 */
async function searchRepoLockFiles(repoFullName, filename, headers) {
  const perPage = 100;
  let page = 1;
  let allItems = [];

  while (true) {
    const q = `filename:${filename} repo:${repoFullName}`;
    const params = new URLSearchParams({
      q,
      per_page: String(perPage),
      page: String(page),
    });

    const url = `${GITHUB_API_URL}/search/code?${params.toString()}`;
    console.error(
      `GitHub search (fallback): ${filename} in ${repoFullName} (page ${page})...`
    );
    const res = await fetch(url, { headers });

    if (res.status === 403) {
      const body = await res.text();
      if (body.toLowerCase().includes("rate limit")) {
        console.error(
          "GitHub rate limit reached (403) on /search/code (repo fallback). Stopping search for this repo."
        );
        break;
      } else {
        throw new Error(`403 error on /search/code (repo fallback): ${body}`);
      }
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(
        `Error calling /search/code (repo fallback) (${res.status} ${res.statusText}) for ${repoFullName}: ${body}`
      );
    }

    const data = await res.json();
    const items = data.items || [];
    allItems = allItems.concat(items);

    if (items.length < perPage || page * perPage >= 1000) {
      break;
    }
    page += 1;
  }

  return allItems;
}

/**
 * Repo-level fallback: use /search/code repo:... if Git trees enumeration fails.
 */
async function fallbackSearchLockFilesForRepo(
  repoFullName,
  headers,
  yarnArray,
  npmArray,
  pnpmArray
) {
  try {
    console.error(`  -> Fallback /search/code for ${repoFullName}...`);

    const yarnItems = await searchRepoLockFiles(repoFullName, "yarn.lock", headers);
    const npmItems = await searchRepoLockFiles(
      repoFullName,
      "package-lock.json",
      headers
    );
    const pnpmItems = await searchRepoLockFiles(
      repoFullName,
      "pnpm-lock.yaml",
      headers
    );

    for (const item of yarnItems) {
      yarnArray.push({ repository: { full_name: repoFullName }, path: item.path });
    }
    for (const item of npmItems) {
      npmArray.push({ repository: { full_name: repoFullName }, path: item.path });
    }
    for (const item of pnpmItems) {
      pnpmArray.push({ repository: { full_name: repoFullName }, path: item.path });
    }
  } catch (e) {
    console.error(
      `  -> Repo fallback /search/code failed for ${repoFullName}: ${e.message}`
    );
  }
}

/**
 * List all repos in an org via /orgs/:org/repos.
 */
async function listOrgRepos(org, headers) {
  const perPage = 100;
  let page = 1;
  const repos = [];

  console.error(`Listing repos for org "${org}" via /orgs/:org/repos...`);

  while (true) {
    const params = new URLSearchParams({
      per_page: String(perPage),
      page: String(page),
      type: "all",
    });

    const url = `${GITHUB_API_URL}/orgs/${org}/repos?${params.toString()}`;
    const res = await fetch(url, { headers });

    if (res.status === 403) {
      const body = await res.text();
      if (body.toLowerCase().includes("rate limit")) {
        console.error(
          "GitHub rate limit reached (403) on /orgs/:org/repos. Stopping repo enumeration."
        );
        break;
      } else {
        throw new Error(`403 error on /orgs/:org/repos: ${body}`);
      }
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(
        `Error calling /orgs/:org/repos (${res.status} ${res.statusText}): ${body}`
      );
    }

    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) {
      break;
    }

    repos.push(...data);

    if (data.length < perPage) {
      break;
    }

    page += 1;
  }

  console.error(
    `  -> Retrieved ${repos.length} repos in total for organization "${org}".`
  );
  return repos;
}

/**
 * Discover yarn.lock / package-lock.json / pnpm-lock.yaml by walking Git trees
 * of the default branches of all repos in the org.
 */
async function listLockFilesViaTrees(org, headers) {
  const repos = await listOrgRepos(org, headers);
  console.error(
    `Discovering lockfiles via Git trees across ${repos.length} repos...`
  );
  const yarn = [];
  const npm = [];
  const pnpm = [];

  for (let index = 0; index < repos.length; index++) {
    const repo = repos[index];
    const repoFullName = repo.full_name;

    if (repo.archived) {
      console.error(
        `[${index + 1}/${repos.length}] Archived repo, skipping: ${repoFullName}`
      );
      continue;
    }

    const defaultBranch = repo.default_branch || "main";

    console.error(
      `[${index + 1}/${repos.length}] Scanning Git tree of ${repoFullName}@${defaultBranch}...`
    );

    try {
      // 1) Get default branch ref
      const refUrl = `${GITHUB_API_URL}/repos/${repoFullName}/git/refs/heads/${encodeURIComponent(
        defaultBranch
      )}`;
      const refRes = await fetch(refUrl, { headers });

      if (!refRes.ok) {
        const body = await refRes.text();
        if (
          refRes.status === 409 &&
          body.toLowerCase().includes("git repository is empty")
        ) {
          console.error(
            `[${index + 1}/${repos.length}] Empty repo, skipping: ${repoFullName}@${defaultBranch}`
          );
        } else {
          console.error(
            `Unable to get ref for ${repoFullName}@${defaultBranch}: ${refRes.status} ${refRes.statusText}: ${body}`
          );
          await fallbackSearchLockFilesForRepo(
            repoFullName,
            headers,
            yarn,
            npm,
            pnpm
          );
        }
        continue;
      }

      const refData = await refRes.json();
      const sha = refData.object && refData.object.sha;
      if (!sha) {
        console.error(
          `Unexpected ref response for ${repoFullName}@${defaultBranch}, no SHA found.`
        );
        continue;
      }

      // 2) Walk the Git tree recursively
      const treeUrl = `${GITHUB_API_URL}/repos/${repoFullName}/git/trees/${sha}?recursive=1`;
      const treeRes = await fetch(treeUrl, { headers });

      if (!treeRes.ok) {
        const body = await treeRes.text();
        console.error(
          `Error calling /git/trees for ${repoFullName}@${defaultBranch}: ${treeRes.status} ${treeRes.statusText}: ${body}`
        );
        await fallbackSearchLockFilesForRepo(
          repoFullName,
          headers,
          yarn,
          npm,
          pnpm
        );
        continue;
      }

      const treeData = await treeRes.json();
      for (const item of treeData.tree || []) {
        if (item.type !== "blob") continue;
        if (item.path.endsWith("yarn.lock")) {
          yarn.push({ repository: { full_name: repoFullName }, path: item.path });
        } else if (item.path.endsWith("package-lock.json")) {
          npm.push({ repository: { full_name: repoFullName }, path: item.path });
        } else if (item.path.endsWith("pnpm-lock.yaml")) {
          pnpm.push({ repository: { full_name: repoFullName }, path: item.path });
        }
      }
    } catch (e) {
      console.error(
        `Error while enumerating lockfiles in ${repoFullName}@${defaultBranch}: ${e.message}`
      );
      await fallbackSearchLockFilesForRepo(
        repoFullName,
        headers,
        yarn,
        npm,
        pnpm
      );
      continue;
    }
  }

  return { yarn, npm, pnpm };
}

/**
 * Download file content via /repos/:owner/:repo/contents/:path
 */
async function fetchFileContent(repoFullName, path, headers) {
  const encodedPath = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");

  const url = `${GITHUB_API_URL}/repos/${repoFullName}/contents/${encodedPath}`;
  const res = await fetch(url, { headers });

  if (res.status === 404) {
    return null;
  }
  if (!res.ok) {
    const body = await res.text();
    throw new Error(
      `Error fetching content (${res.status} ${res.statusText}) for ${repoFullName}/${path}: ${body}`
    );
  }

  const data = await res.json();
  if (!data.download_url) {
    return null;
  }

  const rawRes = await fetch(data.download_url);
  if (!rawRes.ok) {
    const body = await rawRes.text();
    throw new Error(
      `Error downloading raw file (${rawRes.status} ${rawRes.statusText}) for ${data.download_url}: ${body}`
    );
  }

  return await rawRes.text();
}

/**
 * Analyse a package-lock.json and return a list of compromised { name, version }.
 */
function checkPackageLock(content, isCompromised) {
  let data;
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }

  const matchesMap = new Map(); // key: "name@version"

  const addMatch = (name, version) => {
    if (!isCompromised(name, version)) return;
    const key = `${name}@${version || "?"}`;
    if (!matchesMap.has(key)) {
      matchesMap.set(key, { name, version: version || null });
    }
  };

  const walkDeps = (deps) => {
    if (!deps || typeof deps !== "object") return;
    for (const [name, info] of Object.entries(deps)) {
      if (!info || typeof info !== "object") continue;
      const version = info.version;
      addMatch(name, version);
      if (info.dependencies && typeof info.dependencies === "object") {
        walkDeps(info.dependencies);
      }
    }
  };

  // package-lock v1
  if (data.dependencies && typeof data.dependencies === "object") {
    walkDeps(data.dependencies);
  }

  // package-lock v2/v3: data.packages = { path -> { name, version, ... } }
  if (data.packages && typeof data.packages === "object") {
    for (const info of Object.values(data.packages)) {
      if (!info || typeof info !== "object") continue;
      const name = info.name;
      const version = info.version;
      if (name) {
        addMatch(name, version);
      }
    }
  }

  return Array.from(matchesMap.values());
}

/**
 * Analyse a yarn.lock (Yarn v1/v2) and return a list of compromised { name, version }.
 *
 * Simplified parsing:
 *  - Block starts at a non-indented line ending with ":"
 *  - Extract package names from each specifier (before the last '@')
 *  - Read the "version" line within the block
 */
function checkYarnLock(content, isCompromised) {
  const lines = content.split(/\r?\n/);
  let currentPkgs = [];
  let currentVersion = null;
  const matchesMap = new Map();

  const addCurrentMatches = () => {
    if (!currentPkgs.length) return;
    for (const name of currentPkgs) {
      if (!isCompromised(name, currentVersion)) continue;
      const key = `${name}@${currentVersion || "?"}`;
      if (!matchesMap.has(key)) {
        matchesMap.set(key, { name, version: currentVersion || null });
      }
    }
  };

  for (const rawLine of lines) {
    const line = rawLine;

    // New block?
    if (line && !line.startsWith(" ") && line.trim().endsWith(":")) {
      // Close previous block
      addCurrentMatches();

      const header = line.trim().slice(0, -1); // remove ':'
      const parts = header
        .split(",")
        .map((p) => p.trim().replace(/^"|"$/g, "").replace(/^'|'$/g, ""));

      currentPkgs = [];
      currentVersion = null;

      for (const part of parts) {
        if (!part) continue;
        // e.g. "@scope/name@^1.2.3", "react@^18.2.0"
        const atIndex = part.lastIndexOf("@");
        let name = part;
        if (atIndex > 0) {
          name = part.slice(0, atIndex);
        }
        name = name.trim();
        if (name) currentPkgs.push(name);
      }
    } else if (line.trim().startsWith("version")) {
      // version "1.2.3" / version: "1.2.3" / version 1.2.3
      const trimmed = line.trim();
      let version = null;
      const m = trimmed.match(/^version\s*[:=]?\s*["']?([^"']+)["']?/);
      if (m) {
        version = m[1].trim();
      }
      currentVersion = version;
    }
  }

  // Last block
  addCurrentMatches();

  return Array.from(matchesMap.values());
}

/**
 * Analyse a pnpm-lock.yaml and return a list of compromised { name, version }.
 *
 * Simplified parsing based on the `packages:` section:
 *
 * packages:
 *   "/foo@1.2.3":
 *   "@scope/bar@4.5.6":
 */
function checkPnpmLock(content, isCompromised) {
  const lines = content.split(/\r?\n/);
  const matchesMap = new Map();
  let inPackages = false;

  for (const rawLine of lines) {
    const line = rawLine;
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Enter packages section
    if (!line.startsWith(" ") && trimmed === "packages:") {
      inPackages = true;
      continue;
    }

    // Leave packages section: next top-level block
    if (inPackages && !line.startsWith(" ") && trimmed.endsWith(":")) {
      break;
    }

    if (!inPackages) continue;

    // Package key lines, typically indented by 2 spaces
    //   "  /foo@1.2.3:" or "  \"@scope/bar@4.5.6\":"
    if (/^\s{2}\S/.test(line) && trimmed.endsWith(":")) {
      let key = trimmed.slice(0, -1).trim(); // remove ':' at end
      key = key.replace(/^"|"$/g, "").replace(/^'|'$/g, "");

      const atIndex = key.lastIndexOf("@");
      if (atIndex <= 0) continue;

      let name = key.slice(0, atIndex).trim();
      let version = key.slice(atIndex + 1).trim();

      // Normalize name: remove leading "/" or "/@scope/..."
      if (name.startsWith("/@")) {
        name = name.slice(1); // "@scope/name"
      } else if (name.startsWith("/")) {
        name = name.slice(1); // "foo"
      }

      if (!name) continue;

      if (!isCompromised(name, version)) continue;

      const id = `${name}@${version || "?"}`;
      if (!matchesMap.has(id)) {
        matchesMap.set(id, { name, version: version || null });
      }
    }
  }

  return Array.from(matchesMap.values());
}

/**
 * Main program.
 */
(async () => {
  const { org, token, noVersionCheck, packagesUrl, discoveryMode } = parseArgs();
  const headers = buildGithubHeaders(token);

  // 1) Load compromised package list
  const compromisedMap = await loadCompromisedPackagesFromMarkdown(packagesUrl);
  const isCompromised = buildMatcher(compromisedMap, noVersionCheck);

  // 2) Discover lockfiles in the org
  console.error(`\nScanning GitHub organization "${org}" for lockfiles...\n`);

  let yarnItems = [];
  let pkgLockItems = [];
  let pnpmItems = [];

  if (discoveryMode === "search") {
    console.error("Discovery mode: GitHub /search/code only.");
    yarnItems = await searchLockFiles(org, "yarn.lock", headers);
    pkgLockItems = await searchLockFiles(org, "package-lock.json", headers);
    pnpmItems = await searchLockFiles(org, "pnpm-lock.yaml", headers);
  } else {
    console.error(
      "Discovery mode: Git trees for all repos (default, more exhaustive)."
    );
    try {
      const { yarn, npm, pnpm } = await listLockFilesViaTrees(org, headers);
      yarnItems = yarn;
      pkgLockItems = npm;
      pnpmItems = pnpm;
    } catch (e) {
      console.error(
        `Error while enumerating lockfiles via Git trees: ${e.message}`
      );
      console.error("Falling back to GitHub /search/code for the whole org...");
      yarnItems = await searchLockFiles(org, "yarn.lock", headers);
      pkgLockItems = await searchLockFiles(org, "package-lock.json", headers);
      pnpmItems = await searchLockFiles(org, "pnpm-lock.yaml", headers);
    }
  }

  console.error("Lockfiles discovered:");
  console.error(`  yarn.lock         : ${yarnItems.length}`);
  console.error(`  package-lock.json : ${pkgLockItems.length}`);
  console.error(`  pnpm-lock.yaml    : ${pnpmItems.length}\n`);

  const findings = [];

  // 3) Scan yarn.lock
  for (const item of yarnItems) {
    const repoFullName = item.repository.full_name;
    const path = item.path;

    let content;
    try {
      content = await fetchFileContent(repoFullName, path, headers);
    } catch (e) {
      console.error(`Error fetching ${repoFullName}/${path}: ${e.message}`);
      continue;
    }
    if (!content) continue;

    const matches = checkYarnLock(content, isCompromised);
    if (matches.length > 0) {
      findings.push({
        repo: repoFullName,
        path,
        type: "yarn.lock",
        matches,
      });
    }
  }

  // 4) Scan package-lock.json
  for (const item of pkgLockItems) {
    const repoFullName = item.repository.full_name;
    const path = item.path;

    let content;
    try {
      content = await fetchFileContent(repoFullName, path, headers);
    } catch (e) {
      console.error(`Error fetching ${repoFullName}/${path}: ${e.message}`);
      continue;
    }
    if (!content) continue;

    const matches = checkPackageLock(content, isCompromised);
    if (matches.length > 0) {
      findings.push({
        repo: repoFullName,
        path,
        type: "package-lock.json",
        matches,
      });
    }
  }

  // 5) Scan pnpm-lock.yaml
  for (const item of pnpmItems) {
    const repoFullName = item.repository.full_name;
    const path = item.path;

    let content;
    try {
      content = await fetchFileContent(repoFullName, path, headers);
    } catch (e) {
      console.error(`Error fetching ${repoFullName}/${path}: ${e.message}`);
      continue;
    }
    if (!content) continue;

    const matches = checkPnpmLock(content, isCompromised);
    if (matches.length > 0) {
      findings.push({
        repo: repoFullName,
        path,
        type: "pnpm-lock.yaml",
        matches,
      });
    }
  }

  // 6) Print results
  console.log(""); // clean separation
  if (findings.length === 0) {
    console.log(
      "No Shai-Hulud compromised packages found in yarn.lock / package-lock.json / pnpm-lock.yaml in the organization."
    );
    process.exit(0);
  }

  console.log("Compromised packages detected:");
  console.log("==============================");
  for (const f of findings) {
    console.log(`- ${f.repo} :: ${f.path} (${f.type})`);
    for (const { name, version } of f.matches) {
      if (version) {
        console.log(`    • ${name}@${version}`);
      } else {
        console.log(`    • ${name} (unknown version)`);
      }
    }
    console.log("");
  }
})();
