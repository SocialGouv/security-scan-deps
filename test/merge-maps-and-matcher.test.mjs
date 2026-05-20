import test from "node:test";
import assert from "node:assert/strict";

import { _testInternals } from "../index.mjs";

const {
  mergeCompromisedMaps,
  buildMatcher,
  parseCompromisedPackagesFromColonList,
} = _testInternals;

const makeAllVersionsMap = (entries) => {
  const m = new Map();
  for (const name of entries) {
    m.set(name, new Set());
  }
  return m;
};

const makeVersionedMap = (obj) => {
  const m = new Map();
  for (const [name, versions] of Object.entries(obj)) {
    m.set(name, new Set(versions));
  }
  return m;
};

// --- mergeCompromisedMaps semantics ---

test("mergeCompromisedMaps: prefer specific versions over all-versions when conflicting", () => {
  const allMap = makeAllVersionsMap(["foo"]);
  const verMap = makeVersionedMap({ foo: ["1.0.0", "2.0.0"] });

  const merged1 = mergeCompromisedMaps(allMap, verMap);
  const merged2 = mergeCompromisedMaps(verMap, allMap);

  for (const merged of [merged1, merged2]) {
    const versions = merged.get("foo");
    assert(versions, "foo should exist in merged map");
    assert.equal(versions.size, 2);
    assert(versions.has("1.0.0"));
    assert(versions.has("2.0.0"));
  }
});


test("mergeCompromisedMaps: all-versions preserved when no specific versions exist", () => {
  const allMap = makeAllVersionsMap(["foo"]);
  const other = makeVersionedMap({ bar: ["1.0.0"] });

  const merged = mergeCompromisedMaps(allMap, other);

  const fooVersions = merged.get("foo");
  assert(fooVersions, "foo should exist in merged map");
  assert.equal(fooVersions.size, 0, "foo should remain all-versions-compromised");

  const barVersions = merged.get("bar");
  assert(barVersions, "bar should exist in merged map");
  assert.equal(barVersions.size, 1);
  assert(barVersions.has("1.0.0"));
});


// --- buildMatcher semantics with empty vs non-empty sets ---

test("buildMatcher: empty set => all versions compromised", () => {
  const map = new Map([["foo", new Set()]]);
  const isCompromised = buildMatcher(map, false);

  assert.equal(isCompromised("foo", "1.0.0"), true);
  assert.equal(isCompromised("foo", "999.0.0"), true);
  assert.equal(isCompromised("foo", null), true);
  assert.equal(isCompromised("bar", "1.0.0"), false);
});


test("buildMatcher: non-empty set => only listed versions compromised", () => {
  const map = new Map([["foo", new Set(["1.0.0"] )]]);
  const isCompromised = buildMatcher(map, false);

  assert.equal(isCompromised("foo", "1.0.0"), true);
  assert.equal(isCompromised("foo", "2.0.0"), false);
  assert.equal(isCompromised("foo", null), true, "unknown version stays conservative");
  assert.equal(isCompromised("bar", "1.0.0"), false);
});

// --- buildMatcher: wildcard versions with x ---

test("buildMatcher: wildcard 15.0.x matches only 15.0.*", () => {
  const map = makeVersionedMap({ foo: ["15.0.x"] });
  const isCompromised = buildMatcher(map, false);

  assert.equal(isCompromised("foo", "15.0.0"), true);
  assert.equal(isCompromised("foo", "15.0.99"), true);
  assert.equal(isCompromised("foo", "15.1.0"), false);
  assert.equal(isCompromised("foo", "14.9.9"), false);
});


test("buildMatcher: wildcard 15.x matches any 15.*.*", () => {
  const map = makeVersionedMap({ foo: ["15.x"] });
  const isCompromised = buildMatcher(map, false);

  assert.equal(isCompromised("foo", "15.0.0"), true);
  assert.equal(isCompromised("foo", "15.9.9"), true);
  assert.equal(isCompromised("foo", "14.9.9"), false);
  assert.equal(isCompromised("foo", "16.0.0"), false);
});

// --- buildMatcher: range expressions ---

test("buildMatcher: range >=15.0.0 <15.0.5", () => {
  const map = makeVersionedMap({ foo: [">=15.0.0 <15.0.5"] });
  const isCompromised = buildMatcher(map, false);

  assert.equal(isCompromised("foo", "15.0.0"), true);
  assert.equal(isCompromised("foo", "15.0.1"), true);
  assert.equal(isCompromised("foo", "15.0.4"), true);
  assert.equal(isCompromised("foo", "15.0.5"), false);
  assert.equal(isCompromised("foo", "14.9.9"), false);
  assert.equal(isCompromised("foo", "15.1.0"), false);
});


// --- parseCompromisedPackagesFromColonList ---

test("parseCompromisedPackagesFromColonList: ignores comments and blanks", () => {
  const text = [
    "# Header comment",
    "",
    "axios:1.14.1",
    "  ",
    "# Section break",
    "@antv/g2:5.5.8",
  ].join("\n");
  const map = parseCompromisedPackagesFromColonList(text);
  assert.equal(map.size, 2);
  assert([...map.get("axios")].join() === "1.14.1");
  assert([...map.get("@antv/g2")].join() === "5.5.8");
});

test("parseCompromisedPackagesFromColonList: strips npm: prefix, skips pypi:", () => {
  const text = [
    "npm:lodash:4.17.20",
    "npm:@scope/pkg:2.0.0",
    "pypi:requests:2.31.0",
  ].join("\n");
  const map = parseCompromisedPackagesFromColonList(text);
  assert.equal(map.size, 2);
  assert(map.has("lodash"));
  assert(map.has("@scope/pkg"));
  assert(!map.has("requests"));
});

test("parseCompromisedPackagesFromColonList: dedupes versions for same package", () => {
  const text = [
    "size-sensor:1.0.4",
    "size-sensor:1.1.4",
    "size-sensor:1.2.4",
    "size-sensor:1.1.4",
  ].join("\n");
  const map = parseCompromisedPackagesFromColonList(text);
  const versions = [...map.get("size-sensor")].sort();
  assert.deepEqual(versions, ["1.0.4", "1.1.4", "1.2.4"]);
});

test("buildMatcher: combination of exact, wildcard and range", () => {
  const map = makeVersionedMap({
    foo: ["1.0.0", "2.x", ">=3.0.0 <3.0.3"],
  });
  const isCompromised = buildMatcher(map, false);

  // exact
  assert.equal(isCompromised("foo", "1.0.0"), true);
  assert.equal(isCompromised("foo", "1.0.1"), false);

  // wildcard
  assert.equal(isCompromised("foo", "2.0.0"), true);
  assert.equal(isCompromised("foo", "2.5.1"), true);
  assert.equal(isCompromised("foo", "3.2.0"), false);

  // range
  assert.equal(isCompromised("foo", "3.0.0"), true);
  assert.equal(isCompromised("foo", "3.0.2"), true);
  assert.equal(isCompromised("foo", "3.0.3"), false);
});
