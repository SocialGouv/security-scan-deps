#!/usr/bin/env node
/* index.mjs
 *
 * Scan a GitHub organization (or a single repo, or a local directory) for
 * dependencies that appear in one or more vulnerable package lists
 * (e.g. DataDog/Tenable Shai‑Hulud IOC list, CERT-FR advisories, or a
 * custom CSV/Markdown list) in yarn.lock / package-lock.json /
 * pnpm-lock.yaml / bun.lock.
 *
 * Requirements:
 *   - Node.js >= 18 (for native fetch)
 *   - A GitHub token with read access to the org's repositories
 *     (GITHUB_TOKEN env var or --token).
 */

import { pathToFileURL } from "node:url";
import fs from "node:fs/promises";
import path from "node:path";

const GITHUB_API_URL = "https://api.github.com";

// Default per-request delay for GitHub API calls (in ms)
const DEFAULT_GITHUB_DELAY_MS = 0;

// Maximum wait time when rate-limited, in milliseconds (safety cap)
const MAX_RATE_LIMIT_WAIT_MS = 2 * 60 * 1000; // 2 minutes

// Default URL to DataDog's consolidated CSV of compromised packages
const DEFAULT_PACKAGE_LIST_URL =
  "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv";

// Legacy Tenable Markdown list (list.md)
const TENABLE_MARKDOWN_URL =
  "https://github.com/tenable/shai-hulud-second-coming-affected-packages/raw/main/list.md";

/**
 * CLI args parsing.
 *
 * Remote mode (GitHub, default):
 *   node index.mjs <org> [--repo REPO] [--token TOKEN] [--no-version-check]
 *                      [--packages-url URL] [--packages-file PATH]
 *                      [--discovery MODE]
 *
 * Local mode (scan current directory, no GitHub):
 *   node index.mjs --local [--no-version-check]
 *                           [--packages-url URL] [--packages-file PATH]
 */
function parseArgs() {
  const argv = process.argv.slice(2);

  const usage =
    "Usage: node index.mjs <org> [--repo REPO] [--token TOKEN] [--no-version-check] [--packages-url URL] [--packages-file PATH] [--discovery MODE] [--github-delay-ms MS]\n" +
    "   or: node index.mjs --local [--no-version-check] [--packages-url URL] [--packages-file PATH]";

  if (argv.length === 0) {
    console.error(usage);
    process.exit(1);
  }

  let mode = "remote"; // "remote" (GitHub) or "local" (current directory)
  let org = null;
  let repo = null;
  let token = process.env.GITHUB_TOKEN || null;
  let noVersionCheck = false;
  let packagesUrl = DEFAULT_PACKAGE_LIST_URL;
  let packagesFile = null;
  let discoveryMode = "trees"; // "trees" (default) or "search"
  let githubDelayMs = Number.parseInt(process.env.GITHUB_DELAY_MS || "", 10);
  if (!Number.isFinite(githubDelayMs) || githubDelayMs < 0) {
    githubDelayMs = DEFAULT_GITHUB_DELAY_MS;
  }

  let i = 0;
  if (argv[0] === "--local") {
    mode = "local";
    i = 1;
  } else {
    if (argv[0].startsWith("-")) {
      console.error(usage);
      process.exit(1);
    }
    org = argv[0];
    i = 1;
  }

  for (; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--no-version-check") {
      noVersionCheck = true;
    } else if (arg === "--packages-url" && argv[i + 1]) {
      packagesUrl = argv[++i];
    } else if (arg === "--packages-file" && argv[i + 1]) {
      packagesFile = argv[++i];
    } else if (mode === "remote" && arg === "--token" && argv[i + 1]) {
      token = argv[++i];
    } else if (mode === "remote" && arg === "--repo" && argv[i + 1]) {
      repo = argv[++i];
    } else if (mode === "remote" && arg === "--discovery" && argv[i + 1]) {
      discoveryMode = argv[++i];
    } else if (arg === "--github-delay-ms" && argv[i + 1]) {
      const val = Number.parseInt(argv[++i], 10);
      if (Number.isFinite(val) && val >= 0) {
        githubDelayMs = val;
      }
    }
  }

  if (mode === "remote" && !token) {
    console.error(
      "Error: no GitHub token provided. Use --token or the GITHUB_TOKEN environment variable."
    );
    process.exit(1);
  }

  return {
    mode,
    org,
    repo,
    token,
    noVersionCheck,
    packagesUrl,
    packagesFile,
    discoveryMode,
    githubDelayMs,
  };
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

function sleep(ms) {
  if (!ms || ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Create a small GitHub client wrapper that handles rate limiting and per-request delay.
 */
function makeGithubClient({ headers, delayMs = DEFAULT_GITHUB_DELAY_MS, maxRetries = 3 } = {}) {
  const baseHeaders = headers || {};

  const githubFetch = async (url, options = {}) => {
    const { method = "GET", body, headers: extraHeaders } = options;
    const finalHeaders = { ...baseHeaders, ...extraHeaders };

    let attempt = 0;

    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (delayMs && delayMs > 0) {
        await sleep(delayMs);
      }

      const res = await fetch(url, {
        method,
        headers: finalHeaders,
        body,
      });

      if (res.status !== 403) {
        return res;
      }

      const lowerBody = (await res.clone().text()).toLowerCase();
      const remaining = Number.parseInt(
        res.headers.get("x-ratelimit-remaining") || "",
        10
      );

      if (
        (Number.isFinite(remaining) && remaining === 0) ||
        lowerBody.includes("rate limit")
      ) {
        const reset = Number.parseInt(
          res.headers.get("x-ratelimit-reset") || "",
          10
        );
        let waitMs = Number.isFinite(reset)
          ? reset * 1000 - Date.now()
          : 0;
        if (!Number.isFinite(waitMs) || waitMs < 0) {
          waitMs = 0;
        }
        if (waitMs > MAX_RATE_LIMIT_WAIT_MS) {
          waitMs = MAX_RATE_LIMIT_WAIT_MS;
        }
        if (waitMs < 1000) {
          waitMs = 1000;
        }

        attempt += 1;
        if (attempt > maxRetries) {
          console.error(
            `GitHub rate limit reached, giving up after ${maxRetries} retries. Last wait would have been ${waitMs}ms.\n` +
              `  URL: ${url}`
          );
          return res;
        }

        console.error(
          `GitHub rate limit reached (attempt ${attempt}/${maxRetries}). Waiting ${Math.round(
            waitMs / 1000
          )}s before retrying...`
        );
        await sleep(waitMs);
        continue;
      }

      // Non rate-limit 403: just return and let callers handle
      return res;
    }
  };

  return {
    fetch: githubFetch,
  };
}

/**
 * Parse compromised packages from a Markdown list (Tenable-style list.md).
 *
 * Returns Map<string, Set<string>> where:
 *   - key    : npm package name (e.g. "@scope/pkg" or "lodash")
 *   - values : set of malicious versions (empty Set => all versions)
 */
function parseCompromisedPackagesFromMarkdown(text) {
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

  return compromised;
}

/**
 * Parse compromised packages from DataDog's consolidated CSV.
 *
 * CSV format (simplified):
 *   package_name,package_versions,sources
 *   foo,1.0.0,"datadog, ..."
 *   bar,"1.0.0, 2.0.0","datadog, ..."
 *
 * Semantics:
 *   - If package_versions is empty => all versions compromised (empty Set)
 *   - Otherwise, comma-separated list of specific versions.
 */
function parseCompromisedPackagesFromCsv(text) {
  const compromised = new Map();
  const lines = text.split(/\r?\n/);
  if (lines.length === 0) return compromised;

  const splitCsvLine = (line) => {
    const result = [];
    let current = "";
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === "\"") {
        if (inQuotes && line[i + 1] === "\"") {
          // Escaped quote ""
          current += "\"";
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === "," && !inQuotes) {
        result.push(current);
        current = "";
      } else {
        current += ch;
      }
    }
    result.push(current);
    return result;
  };

  const unquote = (s) => {
    const trimmed = s.trim();
    if (trimmed.length >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
      return trimmed.slice(1, -1);
    }
    return trimmed;
  };

  let startIndex = 0;
  if (lines[0].toLowerCase().startsWith("package_name,")) {
    startIndex = 1; // skip header
  }

  for (let i = startIndex; i < lines.length; i++) {
    const rawLine = lines[i];
    if (!rawLine || !rawLine.trim()) continue;

    const cols = splitCsvLine(rawLine);
    if (cols.length === 0) continue;

    const name = unquote(cols[0]);
    if (!name) continue;

    const rawVersions = cols.length > 1 ? unquote(cols[1]) : "";
    const versionsCell = rawVersions.trim();

    if (!compromised.has(name)) {
      compromised.set(name, new Set());
    }
    const versionsSet = compromised.get(name);

    if (!versionsCell) {
      // No version specified => all versions considered compromised
      // Convention: empty Set => all versions
      versionsSet.clear();
      continue;
    }

    // If we've already marked this package as "all versions" compromised,
    // do not add specific versions.
    if (versionsSet.size === 0) {
      continue;
    }

    for (const part of versionsCell.split(",")) {
      const v = part.trim();
      if (v) {
        versionsSet.add(v);
      }
    }
  }

  return compromised;
}

/**
 * Merge multiple compromised maps.
 * If any map marks a package as "all versions" (empty Set), the result is all versions.
 */
function mergeCompromisedMaps(...maps) {
  const result = new Map();

  for (const m of maps) {
    for (const [name, versions] of m.entries()) {
      if (!result.has(name)) {
        result.set(name, new Set(versions));
        continue;
      }

      const existing = result.get(name);

      // Merge semantics:
      // - Empty Set => "all versions compromised"
      // - Prefer specific versions over "all versions" when they conflict
      if (existing.size === 0 && versions.size === 0) {
        // Both sources say "all versions" -> keep as all versions
        continue;
      }

      if (existing.size === 0 && versions.size > 0) {
        // Narrow from "all versions" to specific versions
        for (const v of versions) {
          existing.add(v);
        }
        continue;
      }

      if (existing.size > 0 && versions.size === 0) {
        // Already have specific versions; ignore broader "all versions" signal
        continue;
      }

      for (const v of versions) {
        existing.add(v);
      }
    }
  }

  return result;
}

/**
 * Load compromised packages from a remote URL (CSV or Markdown).
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

  let compromised;
  if (/\.csv($|[?#])/i.test(fetchUrl)) {
    compromised = parseCompromisedPackagesFromCsv(text);
    console.error(
      `  -> ${compromised.size} compromised packages parsed from CSV.`
    );
  } else {
    compromised = parseCompromisedPackagesFromMarkdown(text);
    console.error(
      `  -> ${compromised.size} compromised packages parsed from markdown.`
    );
  }

  if (compromised.size === 0) {
    console.error(
      "Warning: no entries found in package list. The format may have changed, or the parser is too strict."
    );
  }

  return compromised;
}

async function loadCompromisedPackages({ packagesUrl, packagesFile }) {
  if (packagesFile) {
    console.error(
      `Loading compromised package list from local file ${packagesFile}...`
    );

    let text;
    try {
      text = await fs.readFile(packagesFile, "utf8");
    } catch (e) {
      throw new Error(
        `Failed to read local package list file "${packagesFile}": ${e.message}`
      );
    }

    const ext = path.extname(packagesFile).toLowerCase();
    let compromised;
    if (ext === ".csv") {
      compromised = parseCompromisedPackagesFromCsv(text);
      console.error(
        `  -> ${compromised.size} compromised packages parsed from CSV.`
      );
    } else {
      compromised = parseCompromisedPackagesFromMarkdown(text);
      console.error(
        `  -> ${compromised.size} compromised packages parsed from markdown.`
      );
    }

    if (compromised.size === 0) {
      console.error(
        "Warning: no entries found in package list. The format may have changed, or the parser is too strict."
      );
    }

    return compromised;
  }

  // No local file: use remote lists.
  // If the caller did not override the packages URL, aggregate DataDog CSV
  // and the legacy Tenable markdown list.
  if (packagesUrl === DEFAULT_PACKAGE_LIST_URL) {
    console.error(
      "Using aggregated package list: DataDog CSV + Tenable Markdown (list.md)."
    );
    const datadog = await loadCompromisedPackagesFromMarkdown(
      DEFAULT_PACKAGE_LIST_URL
    );
    const tenable = await loadCompromisedPackagesFromMarkdown(
      TENABLE_MARKDOWN_URL
    );
    return mergeCompromisedMaps(datadog, tenable);
  }

  // If the user explicitly provided a URL, keep single-source behavior.
  return loadCompromisedPackagesFromMarkdown(packagesUrl);
}

/**
 * Parse a numeric semver-like version string into { major, minor, patch }.
 * - Extracts the first "MAJOR.MINOR.PATCH" triple it finds.
 * - Ignores any pre-release / build metadata.
 */
function parseNumericVersion(str) {
  if (typeof str !== "string") return null;
  const m = str.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return {
    major: Number.parseInt(m[1], 10),
    minor: Number.parseInt(m[2], 10),
    patch: Number.parseInt(m[3], 10),
  };
}

/**
 * Parse a wildcard pattern like "15.0.x" or "15.x" or "x" into numeric segments
 * where any segment equal to null is a wildcard.
 */
function parseWildcardPattern(str) {
  if (typeof str !== "string") return null;
  const parts = str.split(".");
  if (parts.length === 0 || parts.length > 3) return null;

  const segs = [null, null, null];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i].trim();
    if (!part || part.toLowerCase() === "x") {
      segs[i] = null; // wildcard
    } else if (/^\d+$/.test(part)) {
      segs[i] = Number.parseInt(part, 10);
    } else {
      // Not a pure number or 'x' -> not a valid simple wildcard pattern
      return null;
    }
  }

  return {
    major: segs[0],
    minor: segs[1],
    patch: segs[2],
  };
}

/**
 * Compare two numeric versions a vs b.
 * Returns -1 if a<b, 0 if a==b, 1 if a>b.
 */
function compareNumericVersions(a, b) {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return 0;
}

/**
 * A single comparator inside a range expression, e.g. ">=15.0.0".
 * op is one of '<', '<=', '>', '>=', '='.
 */
function parseRangeComparator(token) {
  const m = token.match(/^(<=|>=|<|>|=)(\d+\.\d+\.\d+)/);
  if (!m) return null;
  const op = m[1];
  const version = parseNumericVersion(m[2]);
  if (!version) return null;
  return { op, version };
}

/**
 * Parse a range expression consisting of one or more comparators separated
 * by whitespace, e.g. ">=15.0.0 <15.0.5".
 * Returns an array of comparators, or null if invalid.
 */
function parseRangeExpression(str) {
  if (typeof str !== "string") return null;
  const tokens = str
    .split(/\s+/)
    .map((t) => t.trim())
    .filter(Boolean);
  if (tokens.length === 0) return null;

  const comparators = [];
  for (const token of tokens) {
    const cmp = parseRangeComparator(token);
    if (!cmp) return null;
    comparators.push(cmp);
  }
  return comparators;
}

/**
 * Check a single comparator (op, version) against an actual numeric version.
 */
function compareNumericWithComparator(actual, comparator) {
  const cmp = compareNumericVersions(actual, comparator.version);
  switch (comparator.op) {
    case "<":
      return cmp < 0;
    case "<=":
      return cmp <= 0;
    case ">":
      return cmp > 0;
    case ">=":
      return cmp >= 0;
    case "=":
      return cmp === 0;
    default:
      return false;
  }
}

/**
 * Match a numeric version against a wildcard pattern.
 */
function matchWildcard(numericVersion, pattern) {
  if (!numericVersion || !pattern) return false;
  if (pattern.major != null && numericVersion.major !== pattern.major) return false;
  if (pattern.minor != null && numericVersion.minor !== pattern.minor) return false;
  if (pattern.patch != null && numericVersion.patch !== pattern.patch) return false;
  return true;
}

/**
 * Build a matcher function: (name, version) => boolean
 *  - noVersionCheck = true => match by name only
 *  - otherwise, check known vulnerable versions (exact, wildcard, ranges)
 */
function buildMatcher(compromisedMap, noVersionCheck) {
  // Cache compiled matchers per package name so we only parse expressions once.
  const compiledPerPackage = new Map();

  const compileVersionsSet = (versionsSet) => {
    const exactVersions = new Set();
    const wildcardPatterns = [];
    const ranges = [];

    for (const raw of versionsSet) {
      if (typeof raw !== "string") continue;
      const s = raw.trim();
      if (!s) continue;

      // Range expressions start with a comparator (<, <=, >, >=, =)
      if (/^(<=|>=|<|>|=)/.test(s)) {
        const range = parseRangeExpression(s);
        if (range) {
          ranges.push(range);
          continue;
        }
      }

      // Wildcard expressions contain 'x' or 'X'
      if (/[xX]/.test(s)) {
        const pattern = parseWildcardPattern(s);
        if (pattern) {
          wildcardPatterns.push(pattern);
          continue;
        }
      }

      // Fallback: treat as an exact version string
      exactVersions.add(s);
    }

    return (version) => {
      // Exact string match first
      if (exactVersions.has(version)) return true;

      const numeric = parseNumericVersion(version);

      if (numeric) {
        // Wildcards
        for (const pattern of wildcardPatterns) {
          if (matchWildcard(numeric, pattern)) return true;
        }

        // Range expressions: OR between expressions, AND inside each expression
        for (const comparators of ranges) {
          let ok = true;
          for (const comparator of comparators) {
            if (!compareNumericWithComparator(numeric, comparator)) {
              ok = false;
              break;
            }
          }
          if (ok) return true;
        }
      }

      return false;
    };
  };

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

    let compiled = compiledPerPackage.get(name);
    if (!compiled) {
      compiled = compileVersionsSet(versions);
      compiledPerPackage.set(name, compiled);
    }

    return compiled(version);
  };
}

// Internal exports for testing specific behaviors
export const _testInternals = {
  mergeCompromisedMaps,
  buildMatcher,
};

/**
 * Best-effort normalization for Bun's bun.lock JSONC format.
 * Strips line and block comments plus trailing commas so JSON.parse succeeds.
 */
function normalizeJsoncToJson(text) {
  if (typeof text !== "string") return text;

  // Remove // line comments (but avoid stripping URLs like "http://")
  let withoutLineComments = text.replace(/(^|[^:])\/\/.*$/gm, (match, prefix) => prefix);

  // Remove /* block */ comments
  let withoutComments = withoutLineComments.replace(/\/\*[\s\S]*?\*\//g, "");

  // Remove trailing commas before } or ]
  let withoutTrailingCommas = withoutComments.replace(/,\s*([}\]])/g, "$1");

  return withoutTrailingCommas;
}

/**
 * Try to extract a semver-like version from a Bun resolution string.
 * Examples:
 *   "foo@1.2.3" -> "1.2.3"
 *   "foo@npm:bar@1.2.3" -> "1.2.3"
 *   "uWebSockets.js@github:uNetworking/uWebSockets.js#6609a88" -> null
 */
function extractVersionFromResolution(str) {
  if (typeof str !== "string") return null;
  const match = str.match(/(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)/);
  return match ? match[1] : null;
}

/**
 * Search all files with a given filename in an org using /search/code.
 * Limited to 1000 results by GitHub.
 */
async function searchLockFiles(org, filename, githubClient) {
  const { fetch: githubFetch } = githubClient;
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
    const res = await githubFetch(url);

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
async function searchRepoLockFiles(repoFullName, filename, githubClient) {
  const { fetch: githubFetch } = githubClient;
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
    const res = await githubFetch(url);

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
  githubClient,
  yarnArray,
  npmArray,
  pnpmArray,
  bunArray
) {
  try {
    console.error(`  -> Fallback /search/code for ${repoFullName}...`);

    const yarnItems = await searchRepoLockFiles(
      repoFullName,
      "yarn.lock",
      githubClient
    );
    const npmItems = await searchRepoLockFiles(
      repoFullName,
      "package-lock.json",
      githubClient
    );
    const pnpmItems = await searchRepoLockFiles(
      repoFullName,
      "pnpm-lock.yaml",
      githubClient
    );
    const bunItems = await searchRepoLockFiles(
      repoFullName,
      "bun.lock",
      githubClient
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
    for (const item of bunItems) {
      bunArray.push({ repository: { full_name: repoFullName }, path: item.path });
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
async function listOrgRepos(org, githubClient) {
  const { fetch: githubFetch } = githubClient;
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
    const res = await githubFetch(url);

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
async function listLockFilesViaTreesForRepos(
  repos,
  githubClient,
  { includeArchived = false } = {}
) {
  const { fetch: githubFetch } = githubClient;

  console.error(
    `Discovering lockfiles via Git trees across ${repos.length} repos...`
  );
  const yarn = [];
  const npm = [];
  const pnpm = [];
  const bun = [];

  for (let index = 0; index < repos.length; index++) {
    const repo = repos[index];
    const repoFullName = repo.full_name;

    if (repo.archived && !includeArchived) {
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
      const refRes = await githubFetch(refUrl);

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
            githubClient,
            yarn,
            npm,
            pnpm,
            bun
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
      const treeRes = await githubFetch(treeUrl);

      if (!treeRes.ok) {
        const body = await treeRes.text();
        console.error(
          `Error calling /git/trees for ${repoFullName}@${defaultBranch}: ${treeRes.status} ${treeRes.statusText}: ${body}`
        );
          await fallbackSearchLockFilesForRepo(
            repoFullName,
            githubClient,
            yarn,
            npm,
            pnpm,
            bun
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
        } else if (item.path.endsWith("bun.lock")) {
          bun.push({ repository: { full_name: repoFullName }, path: item.path });
        }
      }
    } catch (e) {
      console.error(
        `Error while enumerating lockfiles in ${repoFullName}@${defaultBranch}: ${e.message}`
      );
      await fallbackSearchLockFilesForRepo(
        repoFullName,
        githubClient,
        yarn,
        npm,
        pnpm,
        bun
      );
      continue;
    }
  }

  return { yarn, npm, pnpm, bun };
}

async function listLockFilesViaTrees(org, githubClient) {
  const repos = await listOrgRepos(org, githubClient);
  return listLockFilesViaTreesForRepos(repos, githubClient, { includeArchived: false });
}

async function listLockFilesViaTreesForRepoFullName(repoFullName, githubClient) {
  const { fetch: githubFetch } = githubClient;
  console.error(
    `Listing single repo "${repoFullName}" via /repos/:owner/:repo...`
  );
  const url = `${GITHUB_API_URL}/repos/${repoFullName}`;
  const res = await githubFetch(url);

  if (!res.ok) {
    const body = await res.text();
    throw new Error(
      `Error calling /repos/${repoFullName} (${res.status} ${res.statusText}): ${body}`
    );
  }

  const repo = await res.json();
  return listLockFilesViaTreesForRepos([repo], githubClient, { includeArchived: true });
}

/**
 * Download file content via /repos/:owner/:repo/contents/:path
 */
async function fetchFileContent(repoFullName, path, githubClient) {
  const { fetch: githubFetch } = githubClient;
  const encodedPath = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");

  const url = `${GITHUB_API_URL}/repos/${repoFullName}/contents/${encodedPath}`;
  const res = await githubFetch(url);

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
export function checkPackageLock(content, isCompromised) {
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
export function checkYarnLock(content, isCompromised) {
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
 *
 * We also try to be alias-aware:
 *   /foo@npm:bar@1.0.0:
 *     name: foo
 *     id: bar/1.0.0
 *   In that case we will consider both "foo" and "bar" as potential
 *   package names for matching against the compromised list.
 */
export function checkPnpmLock(content, isCompromised) {
  const lines = content.split(/\r?\n/);
  const matchesMap = new Map();
  let inPackages = false;

  // State for the current package block
  let currentNames = new Set();
  let currentVersion = null;
  let hasCurrent = false;

  const flushCurrent = () => {
    if (!hasCurrent || currentNames.size === 0) {
      currentNames = new Set();
      currentVersion = null;
      hasCurrent = false;
      return;
    }

    for (const name of currentNames) {
      if (!isCompromised(name, currentVersion)) continue;
      const id = `${name}@${currentVersion || "?"}`;
      if (!matchesMap.has(id)) {
        matchesMap.set(id, { name, version: currentVersion || null });
      }
    }

    currentNames = new Set();
    currentVersion = null;
    hasCurrent = false;
  };

  for (const rawLine of lines) {
    const line = rawLine;
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Enter packages section
    if (!line.startsWith(" ") && trimmed === "packages:") {
      inPackages = true;
      continue;
    }

    if (!inPackages) continue;

    // Leave packages section: next top-level block after packages
    if (!line.startsWith(" ") && trimmed.endsWith(":") && trimmed !== "packages:") {
      flushCurrent();
      break;
    }

    // Package key lines, typically indented by 2 spaces
    //   "  /foo@1.2.3:" or "  \"@scope/bar@4.5.6\":"
    if (/^\s{2}\S/.test(line) && trimmed.endsWith(":")) {
      // Starting a new package block
      flushCurrent();

      let key = trimmed.slice(0, -1).trim(); // remove ':' at end
      key = key.replace(/^"|"$/g, "").replace(/^'|'$/g, "");

      const atIndex = key.lastIndexOf("@");
      if (atIndex > 0) {
        let namePart = key.slice(0, atIndex).trim();
        let versionPart = key.slice(atIndex + 1).trim();

        // Normalize name: remove leading "/" or "/@scope/..."
        if (namePart.startsWith("/@")) {
          namePart = namePart.slice(1); // "@scope/name"
        } else if (namePart.startsWith("/")) {
          namePart = namePart.slice(1); // "foo"
        }

        if (namePart) {
          currentNames.add(namePart);
          currentVersion = versionPart || null;
          hasCurrent = true;
        }
      }

      continue;
    }

    // Inside a package block, collect additional hints for real package name
    if (hasCurrent) {
      // Prefer explicit name: field when present
      if (trimmed.startsWith("name")) {
        const m = trimmed.match(/^name\s*:\s*["']?([^"']+)["']?/);
        if (m && m[1]) {
          currentNames.add(m[1].trim());
        }
      }

      // pnpm often stores an id like "bar/1.0.0" for the real package
      if (trimmed.startsWith("id")) {
        const m = trimmed.match(/^id\s*:\s*["']?([^"']+)["']?/);
        if (m && m[1]) {
          const idValue = m[1].trim();
          const slashIndex = idValue.indexOf("/");
          const idName = slashIndex > 0 ? idValue.slice(0, slashIndex) : idValue;
          if (idName) {
            currentNames.add(idName);
          }
        }
      }
    }
  }

  // Flush the last package block, if any
  flushCurrent();

  return Array.from(matchesMap.values());
}

/**
 * Analyse a bun.lock (Bun text lockfile) and return a list of compromised { name, version }.
 *
 * bun.lock is JSONC; we first normalize it to JSON and then inspect the `packages` map.
 * For each entry:
 *   "name": [resolution, meta, cacheKey]
 * or
 *   "name": { version, resolution, ... }
 */
export function checkBunLock(content, isCompromised) {
  let data;
  try {
    const normalized = normalizeJsoncToJson(content);
    data = JSON.parse(normalized);
  } catch {
    return [];
  }

  const pkgs = data && data.packages;
  if (!pkgs || typeof pkgs !== "object") {
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

  for (const [name, value] of Object.entries(pkgs)) {
    if (!name) continue;
    if (value == null) continue;

    let version = null;

    if (Array.isArray(value)) {
      // Tuple-style: [resolution, meta?, cacheKey?]
      const meta = value[1];
      if (meta && typeof meta === "object" && typeof meta.version === "string") {
        version = meta.version.trim();
      }
      if (!version && typeof value[0] === "string") {
        version = extractVersionFromResolution(value[0]);
      }
    } else if (typeof value === "object") {
      if (typeof value.version === "string") {
        version = value.version.trim();
      } else if (typeof value.resolution === "string") {
        version = extractVersionFromResolution(value.resolution);
      }
    }

    addMatch(name, version);
  }

  return Array.from(matchesMap.values());
}

/**
 * Main program.
 */
function getRepoFullName(org, repoOption) {
  if (!repoOption) return null;
  return repoOption.includes("/") ? repoOption : `${org}/${repoOption}`;
}

async function main() {
  const {
    mode,
    org,
    repo,
    token,
    noVersionCheck,
    packagesUrl,
    packagesFile,
    discoveryMode,
    githubDelayMs,
  } = parseArgs();

  // 1) Load compromised package list
  const compromisedMap = await loadCompromisedPackages({
    packagesUrl,
    packagesFile,
  });
  const isCompromised = buildMatcher(compromisedMap, noVersionCheck);

  let findings = [];

  if (mode === "local") {
    const rootDir = process.cwd();
    findings = await scanLocalDirectory(rootDir, isCompromised);
  } else {
    const headers = buildGithubHeaders(token);
    const githubClient = makeGithubClient({ headers, delayMs: githubDelayMs });
    const repoFullName = getRepoFullName(org, repo);

    const scopeLabel = repoFullName
      ? `repository "${repoFullName}"`
      : `organization "${org}"`;

    // 2) Discover lockfiles in the org or a specific repo
    console.error(`\nScanning GitHub ${scopeLabel} for lockfiles...\n`);

    let yarnItems = [];
    let pkgLockItems = [];
    let pnpmItems = [];
    let bunItems = [];

    if (discoveryMode === "search") {
      console.error("Discovery mode: GitHub /search/code only.");
      if (repoFullName) {
        console.error(`Restricting search to repo ${repoFullName}.`);
        yarnItems = await searchRepoLockFiles(
          repoFullName,
          "yarn.lock",
          githubClient
        );
        pkgLockItems = await searchRepoLockFiles(
          repoFullName,
          "package-lock.json",
          githubClient
        );
        pnpmItems = await searchRepoLockFiles(
          repoFullName,
          "pnpm-lock.yaml",
          githubClient
        );
        bunItems = await searchRepoLockFiles(
          repoFullName,
          "bun.lock",
          githubClient
        );
      } else {
        yarnItems = await searchLockFiles(org, "yarn.lock", githubClient);
        pkgLockItems = await searchLockFiles(org, "package-lock.json", githubClient);
        pnpmItems = await searchLockFiles(org, "pnpm-lock.yaml", githubClient);
        bunItems = await searchLockFiles(org, "bun.lock", githubClient);
      }
    } else {
      console.error(
        "Discovery mode: Git trees for all repos (default, more exhaustive)."
      );
      try {
        let result;
        if (repoFullName) {
          console.error(`Restricting tree discovery to repo ${repoFullName}.`);
          result = await listLockFilesViaTreesForRepoFullName(
            repoFullName,
            githubClient
          );
        } else {
          result = await listLockFilesViaTrees(org, githubClient);
        }

        const { yarn, npm, pnpm, bun } = result;
        yarnItems = yarn;
        pkgLockItems = npm;
        pnpmItems = pnpm;
        bunItems = bun;
      } catch (e) {
        console.error(
          `Error while enumerating lockfiles via Git trees: ${e.message}`
        );
        console.error(
          repoFullName
            ? `Falling back to GitHub /search/code for repo ${repoFullName}...`
            : "Falling back to GitHub /search/code for the whole org..."
        );

        if (repoFullName) {
          yarnItems = await searchRepoLockFiles(
            repoFullName,
            "yarn.lock",
            githubClient
          );
          pkgLockItems = await searchRepoLockFiles(
            repoFullName,
            "package-lock.json",
            githubClient
          );
          pnpmItems = await searchRepoLockFiles(
            repoFullName,
            "pnpm-lock.yaml",
            githubClient
          );
          bunItems = await searchRepoLockFiles(
            repoFullName,
            "bun.lock",
            githubClient
          );
        } else {
          yarnItems = await searchLockFiles(org, "yarn.lock", githubClient);
          pkgLockItems = await searchLockFiles(
            org,
            "package-lock.json",
            githubClient
          );
          pnpmItems = await searchLockFiles(org, "pnpm-lock.yaml", githubClient);
          bunItems = await searchLockFiles(org, "bun.lock", githubClient);
        }
      }
    }

    console.error("Lockfiles discovered:");
    console.error(`  yarn.lock         : ${yarnItems.length}`);
    console.error(`  package-lock.json : ${pkgLockItems.length}`);
    console.error(`  pnpm-lock.yaml    : ${pnpmItems.length}`);
    console.error(`  bun.lock          : ${bunItems.length}\n`);

    // 3) Scan yarn.lock
    for (const item of yarnItems) {
      const repoFullNameForItem = item.repository.full_name;
      const lockPath = item.path;

      let content;
      try {
        content = await fetchFileContent(
          repoFullNameForItem,
          lockPath,
          githubClient
        );
      } catch (e) {
        console.error(
          `Error fetching ${repoFullNameForItem}/${lockPath}: ${e.message}`
        );
        continue;
      }
      if (!content) continue;

      const matches = checkYarnLock(content, isCompromised);
      if (matches.length > 0) {
        findings.push({
          repo: repoFullNameForItem,
          path: lockPath,
          type: "yarn.lock",
          matches,
        });
      }
    }

    // 4) Scan package-lock.json
    for (const item of pkgLockItems) {
      const repoFullNameForItem = item.repository.full_name;
      const lockPath = item.path;

      let content;
      try {
        content = await fetchFileContent(
          repoFullNameForItem,
          lockPath,
          githubClient
        );
      } catch (e) {
        console.error(
          `Error fetching ${repoFullNameForItem}/${lockPath}: ${e.message}`
        );
        continue;
      }
      if (!content) continue;

      const matches = checkPackageLock(content, isCompromised);
      if (matches.length > 0) {
        findings.push({
          repo: repoFullNameForItem,
          path: lockPath,
          type: "package-lock.json",
          matches,
        });
      }
    }

    // 5) Scan pnpm-lock.yaml
    for (const item of pnpmItems) {
      const repoFullNameForItem = item.repository.full_name;
      const lockPath = item.path;

      let content;
      try {
        content = await fetchFileContent(
          repoFullNameForItem,
          lockPath,
          githubClient
        );
      } catch (e) {
        console.error(
          `Error fetching ${repoFullNameForItem}/${lockPath}: ${e.message}`
        );
        continue;
      }
      if (!content) continue;

      const matches = checkPnpmLock(content, isCompromised);
      if (matches.length > 0) {
        findings.push({
          repo: repoFullNameForItem,
          path: lockPath,
          type: "pnpm-lock.yaml",
          matches,
        });
      }
    }

    // 6) Scan bun.lock
    for (const item of bunItems) {
      const repoFullNameForItem = item.repository.full_name;
      const lockPath = item.path;

      let content;
      try {
        content = await fetchFileContent(
          repoFullNameForItem,
          lockPath,
          githubClient
        );
      } catch (e) {
        console.error(
          `Error fetching ${repoFullNameForItem}/${lockPath}: ${e.message}`
        );
        continue;
      }
      if (!content) continue;

      const matches = checkBunLock(content, isCompromised);
      if (matches.length > 0) {
        findings.push({
          repo: repoFullNameForItem,
          path: lockPath,
          type: "bun.lock",
          matches,
        });
      }
    }
  }

  // 7) Print results
  console.log(""); // clean separation
  if (findings.length === 0) {
    console.log(
      "No vulnerable dependencies found in yarn.lock / package-lock.json / pnpm-lock.yaml / bun.lock in the scanned scope."
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
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  // Only run the CLI when this file is the main entrypoint
  // (not when imported from tests or other modules).
  main();
}
