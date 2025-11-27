import test from "node:test";
import assert from "node:assert/strict";

import {
  checkPackageLock,
  checkYarnLock,
  checkPnpmLock,
  checkBunLock,
} from "../index.mjs";

// Helper: simple compromised matcher
const makeMatcher = (set) => (name, version) => {
  const key = `${name}@${version ?? "?"}`;
  return set.has(key);
};

// --- checkPackageLock tests ---

test("checkPackageLock: v1 dependencies recursion and dedup", () => {
  const content = JSON.stringify(
    {
      dependencies: {
        foo: {
          version: "1.0.0",
          dependencies: {
            bar: {
              version: "2.0.0",
            },
          },
        },
      },
    },
    null,
    2
  );

  const compromised = new Set(["foo@1.0.0", "bar@2.0.0"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkPackageLock(content, isCompromised);
  assert.deepEqual(result.sort((a, b) => a.name.localeCompare(b.name)), [
    { name: "bar", version: "2.0.0" },
    { name: "foo", version: "1.0.0" },
  ]);
});


test("checkPackageLock: v2/v3 packages map and dedup between sections", () => {
  const content = JSON.stringify(
    {
      dependencies: {
        foo: { version: "1.0.0" },
      },
      packages: {
        "": { name: "root", version: "0.0.0" },
        "node_modules/foo": { name: "foo", version: "1.0.0" },
        "node_modules/bar": { name: "bar", version: "2.0.0" },
      },
    },
    null,
    2
  );

  const compromised = new Set(["foo@1.0.0", "bar@2.0.0"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkPackageLock(content, isCompromised);
  const sorted = result.sort((a, b) => a.name.localeCompare(b.name));

  // Expect foo and bar once each (no duplicate foo)
  assert.deepEqual(sorted, [
    { name: "bar", version: "2.0.0" },
    { name: "foo", version: "1.0.0" },
  ]);
});


test("checkPackageLock: invalid JSON returns empty array", () => {
  const result = checkPackageLock("not json", () => true);
  assert.deepEqual(result, []);
});

// --- checkYarnLock tests ---

test("checkYarnLock: single dependency", () => {
  const content = [
    "foo@^1.0.0:",
    "  version \"1.2.3\"",
    "",
  ].join("\n");

  const compromised = new Set(["foo@1.2.3"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkYarnLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "foo", version: "1.2.3" }]);
});


test("checkYarnLock: multiple specifiers for same package are deduped", () => {
  const content = [
    "foo@^1.0.0, foo@~1.1.0:",
    "  version \"1.2.3\"",
    "",
  ].join("\n");

  const compromised = new Set(["foo@1.2.3"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkYarnLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "foo", version: "1.2.3" }]);
});


test("checkYarnLock: scoped package", () => {
  const content = [
    '"@scope/bar@^2.0.0":',
    "  version \"2.3.4\"",
    "",
  ].join("\n");

  const compromised = new Set(["@scope/bar@2.3.4"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkYarnLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "@scope/bar", version: "2.3.4" }]);
});


test("checkYarnLock: missing version results in null version in match", () => {
  const content = [
    "baz@^3.0.0:",
    "  resolved \"https://example.com/baz-3.0.0.tgz\"",
    "",
  ].join("\n");

  const compromised = new Set(["baz@?"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkYarnLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "baz", version: null }]);
});


test("checkYarnLock: non-compromised returns empty array", () => {
  const content = [
    "foo@^1.0.0:",
    "  version \"1.2.3\"",
    "",
  ].join("\n");

  const result = checkYarnLock(content, () => false);
  assert.deepEqual(result, []);
});

// --- checkPnpmLock tests ---

test("checkPnpmLock: unscoped package in packages section", () => {
  const content = [
    "packages:",
    "  /foo@1.0.0:",
    "    resolution: { integrity: 'sha512-...' }",
    "",
  ].join("\n");

  const compromised = new Set(["foo@1.0.0"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkPnpmLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "foo", version: "1.0.0" }]);
});


test("checkPnpmLock: alias with name field detects real package", () => {
  const content = [
    "packages:",
    "  /foo@npm:bar@1.0.0:",
    "    name: bar",
    "    resolution: { integrity: 'sha512-...' }",
    "",
  ].join("\n");

  const compromised = new Set(["bar@1.0.0"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkPnpmLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "bar", version: "1.0.0" }]);
});


test("checkPnpmLock: alias with id field detects real package", () => {
  const content = [
    "packages:",
    "  /foo@npm:bar@1.0.0:",
    "    id: bar/1.0.0",
    "    resolution: { integrity: 'sha512-...' }",
    "",
  ].join("\n");

  const compromised = new Set(["bar@1.0.0"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkPnpmLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "bar", version: "1.0.0" }]);
});


test("checkPnpmLock: scoped package with leading slash", () => {
  const content = [
    "packages:",
    "  /@scope/bar@2.0.0:",
    "    resolution: { integrity: 'sha512-...' }",
    "",
  ].join("\n");

  const compromised = new Set(["@scope/bar@2.0.0"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkPnpmLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "@scope/bar", version: "2.0.0" }]);
});


test("checkPnpmLock: multiple entries for same package are deduped", () => {
  const content = [
    "packages:",
    "  /foo@1.0.0:",
    "    resolution: { integrity: 'sha512-...' }",
    "  /foo@1.0.0:",
    "    resolution: { integrity: 'sha512-...' }",
    "",
  ].join("\n");

  const compromised = new Set(["foo@1.0.0"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkPnpmLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "foo", version: "1.0.0" }]);
});


test("checkPnpmLock: stops when leaving packages section", () => {
  const content = [
    "packages:",
    "  /foo@1.0.0:",
    "    resolution: { integrity: 'sha512-...' }",
    "importers:",
    "  .:",
    "    specifiers: {}",
    "",
  ].join("\n");

  const compromised = new Set(["foo@1.0.0"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkPnpmLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "foo", version: "1.0.0" }]);
});


test("checkPnpmLock: non-compromised returns empty array", () => {
  const content = [
    "packages:",
    "  /foo@1.0.0:",
    "    resolution: { integrity: 'sha512-...' }",
    "",
  ].join("\n");

  const result = checkPnpmLock(content, () => false);
  assert.deepEqual(result, []);
});

// --- checkBunLock tests ---

test("checkBunLock: basic package from packages map", () => {
  const content = JSON.stringify(
    {
      lockfileVersion: 0,
      packages: {
        foo: ["foo@1.2.3", {}, "cache-key"],
      },
    },
    null,
    2
  );

  const compromised = new Set(["foo@1.2.3"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkBunLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "foo", version: "1.2.3" }]);
});


test("checkBunLock: non-semver resolution yields null version", () => {
  const content = JSON.stringify(
    {
      packages: {
        "uWebSockets.js": [
          "uWebSockets.js@github:uNetworking/uWebSockets.js#6609a88",
          {},
          "uNetworking-uWebSockets.js-6609a88",
        ],
      },
    },
    null,
    2
  );

  const compromised = new Set(["uWebSockets.js@?"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkBunLock(content, isCompromised);
  assert.deepEqual(result, [
    { name: "uWebSockets.js", version: null },
  ]);
});


test("checkBunLock: JSONC (comments & trailing commas)", () => {
  const content = `{
    // comment about packages
    "packages": {
      "foo": ["foo@1.2.3", {},],
    },
  }`;

  const compromised = new Set(["foo@1.2.3"]);
  const isCompromised = makeMatcher(compromised);

  const result = checkBunLock(content, isCompromised);
  assert.deepEqual(result, [{ name: "foo", version: "1.2.3" }]);
});


test("checkBunLock: non-compromised returns empty array", () => {
  const content = JSON.stringify(
    {
      packages: {
        foo: ["foo@1.2.3", {}, "k"],
      },
    },
    null,
    2
  );

  const result = checkBunLock(content, () => false);
  assert.deepEqual(result, []);
});


test("checkBunLock: invalid JSON returns empty array", () => {
  const result = checkBunLock("not json", () => true);
  assert.deepEqual(result, []);
});
