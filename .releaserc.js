// semantic-release configuration.
//
// Versioning is automated from Conventional Commits:
//   * push to `main` -> stable release (feat -> minor, fix/perf -> patch, ! -> major)
//   * push to `beta` -> prerelease (vX.Y.Z-beta.N)
//
// Dependency bumps intentionally do NOT cut a release on ordinary pushes. Renovate
// labels them fix(deps) (runtime deps), chore(deps) (dev deps / lock maintenance),
// or build(deps) — fix would otherwise trigger a patch via the default rules, so it
// is explicitly suppressed here. A weekly scheduled workflow run (add one in
// release.yml if desired, mirroring AURA's) can set RELEASE_DEPS=true to promote
// accumulated dependency commits to a single patch release.
//
// This file is CommonJS (there is no root package.json with "type": "module");
// semantic-release loads it via cosmiconfig.

const releaseDeps = process.env.RELEASE_DEPS === "true";

// Custom rules are evaluated before commit-analyzer's defaults, and the first
// match wins — so `release: false` on fix(deps) suppresses the default fix->patch.
// chore/build already don't release by default; they only need promotion when
// RELEASE_DEPS is set.
const depReleaseRules = releaseDeps
  ? [
      { type: "fix", scope: "deps", release: "patch" },
      { type: "chore", scope: "deps", release: "patch" },
      { type: "build", scope: "deps", release: "patch" },
    ]
  : [{ type: "fix", scope: "deps", release: false }];

module.exports = {
  branches: ["main", { name: "beta", prerelease: true }],
  tagFormat: "v${version}",
  plugins: [
    ["@semantic-release/commit-analyzer", { releaseRules: depReleaseRules }],
    "@semantic-release/release-notes-generator",
    ["@semantic-release/changelog", { changelogFile: "CHANGELOG.md" }],
    "@semantic-release/github",
    [
      "@semantic-release/git",
      {
        assets: ["CHANGELOG.md"],
        message: "chore(release): v${nextRelease.version} [skip ci]",
      },
    ],
  ],
};
