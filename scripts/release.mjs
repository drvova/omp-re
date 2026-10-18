#!/usr/bin/env node
/**
 * Conventional-Commits version bump.
 *
 * Looks at the commits in a range, decides whether they warrant a release and
 * at what level, and — if so — bumps the version in `package.json` and
 * `.omp-plugin/marketplace.json` (kept in lock-step) and stamps a dated
 * section in `CHANGELOG.md`. It only edits files; the workflow does the git
 * commit / tag / push. Run it locally with `--dry-run` to preview a decision
 * without touching anything.
 *
 * Bump rules (type of the commit's first line, or a `!` / `BREAKING CHANGE`):
 *   breaking → major   (but minor while the version is still 0.x — a stray
 *                        `!` shouldn't silently cut 1.0.0)
 *   feat     → minor
 *   fix,perf → patch
 *   anything else (docs, chore, ci, test, refactor, style, build, release, …)
 *            → no release on its own
 * The highest level across the range wins; an empty result means "no release".
 *
 * Usage:
 *   node scripts/release.mjs <baseRef> <headRef> [--dry-run]
 *   node scripts/release.mjs --dry-run            # preview: last tag..HEAD
 *
 * In CI, baseRef/headRef are the push event's `before` and `after` SHAs, so
 * the range is exactly the commits that just landed on main.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");
const PKG = join(ROOT, "package.json");
const MARKET = join(ROOT, ".omp-plugin", "marketplace.json");
const CHANGELOG = join(ROOT, "CHANGELOG.md");

const argv = process.argv.slice(2);
const dryRun = argv.includes("--dry-run");
const [base, head = "HEAD"] = argv.filter((a) => !a.startsWith("--"));

const LEVELS = ["none", "patch", "minor", "major"];
const rank = (level) => LEVELS.indexOf(level);

/** Run `git log` with the given revision args and split into per-commit messages. */
function gitLog(...revArgs) {
  // %H <unit sep> raw body, commits separated by a record separator.
  const out = execFileSync(
    "git",
    ["-C", ROOT, "log", "--no-merges", "--format=%H%x1f%B%x1e", ...revArgs],
    {
      encoding: "utf-8",
    }
  );
  return out
    .split("\u001E")
    .map((e) => e.trim())
    .filter(Boolean)
    .map((e) => {
      const sep = e.indexOf("\u001F");
      return { hash: e.slice(0, sep), message: e.slice(sep + 1) };
    });
}

/** Resolve the commit range to inspect, tolerating a missing/zero/invalid base. */
function resolveCommits() {
  const isZero = (s) => !s || /^0+$/u.test(s);
  if (!isZero(base)) {
    try {
      return gitLog(`${base}..${head}`);
    } catch {
      // base isn't an ancestor (force-push, shallow clone): fall through.
    }
  }
  try {
    const lastTag = execFileSync(
      "git",
      ["-C", ROOT, "describe", "--tags", "--abbrev=0", head],
      {
        encoding: "utf-8",
      }
    ).trim();
    if (lastTag) {
      return gitLog(`${lastTag}..${head}`);
    }
  } catch {
    // no tags yet.
  }
  // Last resort: just the head commit.
  return gitLog(head, "-1");
}

const TYPE_RE = /^([a-zA-Z]+)(?:\([^)]*\))?(!)?:/u;

/** The release level a single commit implies, or "none". */
function levelOf(message) {
  const subject = message.split("\n")[0].trim();
  const m = TYPE_RE.exec(subject);
  const breakingFooter = /(^|\n)BREAKING[ -]CHANGE:/u.test(message);
  if ((m && m[2] === "!") || breakingFooter) {
    return "major";
  }
  if (!m) {
    return "none";
  }
  const type = m[1].toLowerCase();
  if (type === "feat") {
    return "minor";
  }
  if (type === "fix" || type === "perf") {
    return "patch";
  }
  return "none";
}

/** The level actually applied, capping a breaking change to minor while in 0.x. */
function effectiveLevel(version, level) {
  const maj = Number.parseInt(version.split(".")[0], 10);
  return level === "major" && maj === 0 ? "minor" : level; // a stray `!` shouldn't cut 1.0.0
}

/** Apply a (already-effective) bump level to a semver string. */
function bump(version, level) {
  const [maj, min, pat] = version.split(".").map((n) => Number.parseInt(n, 10));
  if ([maj, min, pat].some(Number.isNaN)) {
    throw new Error(`unparseable version: ${version}`);
  }
  switch (level) {
    case "major": {
      return `${maj + 1}.0.0`;
    }
    case "minor": {
      return `${maj}.${min + 1}.0`;
    }
    case "patch": {
      return `${maj}.${min}.${pat + 1}`;
    }
    default: {
      return version;
    }
  }
}

/** Replace the first `"version": "..."` value in a raw JSON string. */
function setJsonVersion(raw, next) {
  let done = false;
  const out = raw.replace(/("version":\s*")[^"]*(")/u, (_, pre, post) => {
    done = true;
    return `${pre}${next}${post}`;
  });
  if (!done) {
    throw new Error('no "version" field found');
  }
  return out;
}

function emit(outputs) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) {
    return;
  }
  const lines = Object.entries(outputs)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
  writeFileSync(file, `${lines}\n`, { flag: "a" });
}

// --- decide -----------------------------------------------------------------

const commits = resolveCommits();
let level = "none";
const contributing = [];
for (const c of commits) {
  const l = levelOf(c.message);
  if (l !== "none") {
    contributing.push(
      `  ${l.padEnd(5)} ${c.hash.slice(0, 9)} ${c.message.split("\n")[0]}`
    );
  }
  if (rank(l) > rank(level)) {
    level = l;
  }
}

const pkgRaw = readFileSync(PKG, "utf-8");
const current = JSON.parse(pkgRaw).version;

if (level === "none") {
  console.log(
    `No release-worthy commits in range (${commits.length} scanned). Version stays ${current}.`
  );
  emit({
    level: "none",
    previous: current,
    released: "false",
    version: current,
  });
  process.exit(0);
}

const eff = effectiveLevel(current, level);
const next = bump(current, eff);
console.log(
  eff === level
    ? `${eff} bump: ${current} -> ${next}`
    : `${level} change (capped to ${eff} in 0.x): ${current} -> ${next}`
);
console.log("Triggered by:");
console.log(contributing.join("\n"));

if (dryRun) {
  console.log("\n--dry-run: no files written.");
  emit({ level: eff, previous: current, released: "true", version: next });
  process.exit(0);
}

// --- apply -------------------------------------------------------------------

writeFileSync(PKG, setJsonVersion(pkgRaw, next));
writeFileSync(MARKET, setJsonVersion(readFileSync(MARKET, "utf-8"), next));

const date = new Date().toISOString().slice(0, 10);
const changelog = readFileSync(CHANGELOG, "utf-8");
if (changelog.includes("## [Unreleased]")) {
  writeFileSync(
    CHANGELOG,
    changelog.replace(
      /## \[Unreleased\]\n/u,
      `## [Unreleased]\n\n## [${next}] - ${date}\n`
    )
  );
} else {
  console.warn(
    "CHANGELOG.md has no '## [Unreleased]' heading; left untouched."
  );
}

console.log(
  `Wrote ${next} to package.json, .omp-plugin/marketplace.json, CHANGELOG.md.`
);
emit({ level: eff, previous: current, released: "true", version: next });
