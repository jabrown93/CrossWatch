// semantic-release configuration.
//
// Versioning is automated from Conventional Commits:
//   * push to `main` -> stable release (feat -> minor, fix/perf -> patch, ! -> major)
//   * push to `beta` -> prerelease (vX.Y.Z-beta.N)
//
// Renovate (via the shared preset) batches routine updates into chore
// commits by scope: chore(deps) for runtime dependencies (what ships) and
// chore(dev-deps) for dev/test/CI tooling. chore(dev-deps) never releases
// (chore doesn't release by default). chore(deps) intentionally does NOT cut
// a release on ordinary pushes -- it is explicitly suppressed here. The
// weekly scheduled run in .github/workflows/release.yml sets
// RELEASE_DEPS=true, which promotes the accumulated chore(deps) bumps into
// one patch release. fix commits (including fix(deps), when a dependency
// bump requires manual code changes) release immediately through the
// default rules, as does fix(security) for vulnerability fixes. See
// jabrown93/.github's README, "Weekly dependency releases".
//
// This file is CommonJS (there is no root package.json with "type": "module");
// semantic-release loads it via cosmiconfig.

const releaseDeps = process.env.RELEASE_DEPS === "true";

const depReleaseRules = [
  // Required: commit-analyzer evaluates every matching custom rule and keeps
  // the highest release type, so without this a breaking chore(deps)! would
  // match ONLY the suppression rule below and never release. Listed first so
  // the analyzer short-circuits on major.
  { type: "chore", scope: "deps", breaking: true, release: "major" },
  { type: "chore", scope: "deps", release: releaseDeps ? "patch" : false },
];

module.exports = {
  branches: ["main", { name: "beta", prerelease: true }],
  tagFormat: "v${version}",
  plugins: [
    ["@semantic-release/commit-analyzer", { releaseRules: depReleaseRules }],
    "@semantic-release/release-notes-generator",
    ["@semantic-release/changelog", { changelogFile: "CHANGELOG.md" }],
    "@semantic-release/github",
    [
      "@semantic-release/exec",
      {
        // Version-bump commit via GitHub's GraphQL createCommitOnBranch
        // instead of @semantic-release/git: API commits are signed by GitHub
        // and show as Verified, which a local git commit from the CI bot
        // never can be. RELEASE_COMMIT_SCRIPT is exported by the
        // jabrown93/ci/actions/release-commit step in docker-release.yml
        // (workflows-v1.1.0+); written WITHOUT braces because exec runs this
        // through a Lodash template that would evaluate ${...} as JS. The
        // script hard-resets the checkout so the release tag points at the
        // API commit.
        prepareCmd:
          "node $RELEASE_COMMIT_SCRIPT --branch ${branch.name}" +
          " --message 'chore(release): v${nextRelease.version} [skip ci]' --" +
          " CHANGELOG.md",
      },
    ],
  ],
};
