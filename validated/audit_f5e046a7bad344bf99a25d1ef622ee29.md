### Title
Unbounded recursive upstream redirection in `installRun` causes stack-exhaustion DoS via a two-repo cycle - ([File: pkg/cmd/skills/install/install.go])

### Summary
`installRun` recursively calls itself when `checkUpstreamProvenance` reports a redirect target, and there is no cycle/depth tracking across recursive invocations. An attacker who controls two repositories whose `SKILL.md` frontmatter mutually reference each other via `github-repo` metadata can make `gh skill install --upstream <repoA>` recurse indefinitely between the two repos.

### Finding Description
`installRun` resolves the skill, then calls `checkUpstreamProvenance(opts, apiClient, hostname, selectedSkills[0], resolved.SHA)` [1](#0-0)  which fetches the skill's `SKILL.md` and parses a `github-repo` frontmatter field [2](#0-1) . If `opts.Upstream` (the `--upstream` flag) is set, the function unconditionally returns the parsed upstream repo without any user prompt or cycle check: `if opts.Upstream { ...; return upstreamRepo, true, nil }` [3](#0-2) .

Back in `installRun`, when a redirect target is returned, the code mutates `opts.repo`/`opts.SkillSource` in place and calls `installRun(opts)` recursively, reusing the same `*InstallOptions` (including `opts.Upstream`, still `true`): [4](#0-3) .

Because `opts.Upstream` remains `true` across every recursive call, and `checkUpstreamProvenance` only guards against a repo pointing at *itself* (`existingRepo == currentRepoURL`) [5](#0-4) , nothing prevents repo A's `SKILL.md` from pointing to repo B and repo B's `SKILL.md` from pointing back to repo A. Each hop is a genuine (non-tail-call-optimized) Go function call, so the recursion depth grows without bound: `installRun -> checkUpstreamProvenance -> opts.repo = B -> installRun -> checkUpstreamProvenance -> opts.repo = A -> installRun -> ...`. There is no depth counter, visited-set, or maximum-hop check anywhere in the file.

`source.ValidateSupportedHost` is re-checked on every recursive entry [6](#0-5) , so the loop cannot be used to redirect requests to an unsupported/attacker host — it stays confined to `github.com`/tenancy hosts — but this does not stop the cycle itself.

### Impact Explanation
Each iteration of the cycle performs a full skill-discovery/version-resolution HTTP round trip (`resolveVersion`, `discoverSkills`/`DiscoverSkillByPath`, `checkUpstreamProvenance`'s contents-API fetch) plus a new stack frame in `installRun`. This produces unbounded resource consumption (repeated authenticated API calls against attacker-controlled repositories) and unbounded Go call-stack growth, ultimately crashing the `gh` process (stack overflow) or hanging until externally killed — a denial-of-service condition against the invoking user's `gh` CLI process. This matches a "denial of service / resource exhaustion" impact class.

### Likelihood Explanation
Exploitation only requires an unprivileged attacker to publish two ordinary public GitHub repositories, each containing a skill whose `SKILL.md` frontmatter sets `github-repo` to the other repo's URL. The victim must run `gh skill install --upstream <attacker/repoA>` (the `--upstream` flag is required to skip the interactive confirmation prompt that would otherwise let a human notice the loop). This is a plausible scenario since `--upstream` is a documented, discoverable flag intended for exactly this "follow the upstream" use case, and social engineering of the initial command target is explicitly out of scope but not required beyond a normal install invocation of an attacker's repo/skill name.

### Recommendation
Track visited repositories (or a bounded redirect count, e.g., max 1–2 hops) across recursive `installRun` invocations and return an explicit error such as "too many upstream redirects" when the limit is exceeded or a repository is revisited. This check should apply regardless of whether `opts.Upstream` is set or the redirect came from interactive selection.

### Proof of Concept
Add an `httpmock`-based test similar to the existing `TestInstallRun_UpstreamDetection` table (`pkg/cmd/skills/install/install_test.go`), but with two repos whose `SKILL.md` content mutually reference each other:
- `monalisa/repo-a`'s `SKILL.md` frontmatter: `github-repo: https://github.com/monalisa/repo-b`
- `monalisa/repo-b`'s `SKILL.md` frontmatter: `github-repo: https://github.com/monalisa/repo-a`

Register `httpmock` stubs for `resolveVersion`, `discoverTree`, and `contentsAPI` for both repos (as done for `stubResolveVersion`/`stubDiscoverTree`/`stubContentsAPI` in the existing upstream-detection tests, e.g. [7](#0-6) ), then invoke `installRun` with `Upstream: true` and `SkillSource: "monalisa/repo-a"` (mirroring the "non-interactive with --upstream redirects to upstream" test case at [8](#0-7) , but with the cyclic metadata). Assert that `installRun` returns a bounded error (e.g., "too many upstream redirects") rather than recursing until a stack overflow or panic occurs, and that the number of HTTP requests made to the mock registry is bounded (not unbounded/growing).

### Citations

**File:** pkg/cmd/skills/install/install.go (L345-349)
```go
	if len(selectedSkills) == 1 && selectedSkills[0].BlobSHA != "" {
		upstreamRepo, detected, err := checkUpstreamProvenance(opts, apiClient, hostname, selectedSkills[0], resolved.SHA)
		if err != nil {
			return err
		}
```

**File:** pkg/cmd/skills/install/install.go (L364-369)
```go
			opts.repo = upstreamRepo
			opts.SkillSource = ghrepo.FullName(upstreamRepo)
			opts.version = ""
			opts.Pin = ""
			return installRun(opts)
		}
```

**File:** pkg/cmd/skills/install/install.go (L1327-1341)
```go
	existingRepo, _ := result.Metadata.Meta["github-repo"].(string)
	if existingRepo == "" {
		return nil, false, nil
	}

	currentRepoURL := source.BuildRepoURL(hostname, opts.repo.RepoOwner(), opts.repo.RepoName())
	if existingRepo == currentRepoURL {
		return nil, false, nil
	}

	upstreamRepo, parseErr := source.ParseRepoURL(existingRepo)
	if parseErr != nil {
		//nolint:nilerr // invalid repo URL means we can't redirect; install normally
		return nil, false, nil
	}
```

**File:** pkg/cmd/skills/install/install.go (L1349-1352)
```go
	if opts.Upstream {
		fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
		return upstreamRepo, true, nil
	}
```

**File:** internal/skills/source/source.go (L56-68)
```go
func ValidateSupportedHost(host string) error {
	host = normalizeHost(host)
	if host == "" {
		return fmt.Errorf("could not determine repository host")
	}
	if host == SupportedHost || ghauth.IsTenancy(host) {
		return nil
	}
	if ghauth.IsEnterprise(host) {
		return fmt.Errorf("GitHub Skills does not currently support GitHub Enterprise Server; got %s", host)
	}
	return fmt.Errorf("unsupported host for GitHub Skills: %s", host)
}
```

**File:** pkg/cmd/skills/install/install_test.go (L2774-2787)
```go
			stubs: func(reg *httpmock.Registry) {
				stubResolveVersion(reg, "monalisa", "skills-repo", "v1.0.0", "abc123")
				stubDiscoverTree(reg, "monalisa", "skills-repo", "abc123",
					singleSkillTreeJSON("git-commit", "treeSHA", "blobSHA"))
				stubContentsAPI(reg, "monalisa", "skills-repo",
					"skills/git-commit/SKILL.md", republishedContent)
				stubResolveVersion(reg, "monalisa", "original-skills", "v2.0.0", "upstream456")
				stubDiscoverTree(reg, "monalisa", "original-skills", "upstream456",
					singleSkillTreeJSON("git-commit", "upTreeSHA", "upBlobSHA"))
				stubContentsAPI(reg, "monalisa", "original-skills",
					"skills/git-commit/SKILL.md", gitCommitContent)
				stubInstallFiles(reg, "monalisa", "original-skills",
					"upTreeSHA", "upBlobSHA", gitCommitContent)
			},
```

**File:** pkg/cmd/skills/install/install_test.go (L2843-2876)
```go
			name:  "non-interactive with --upstream redirects to upstream",
			isTTY: false,
			stubs: func(reg *httpmock.Registry) {
				stubResolveVersion(reg, "monalisa", "skills-repo", "v1.0.0", "abc123")
				stubDiscoverTree(reg, "monalisa", "skills-repo", "abc123",
					singleSkillTreeJSON("git-commit", "treeSHA", "blobSHA"))
				stubContentsAPI(reg, "monalisa", "skills-repo",
					"skills/git-commit/SKILL.md", republishedContent)
				stubResolveVersion(reg, "monalisa", "original-skills", "v2.0.0", "upstream456")
				stubDiscoverTree(reg, "monalisa", "original-skills", "upstream456",
					singleSkillTreeJSON("git-commit", "upTreeSHA", "upBlobSHA"))
				stubContentsAPI(reg, "monalisa", "original-skills",
					"skills/git-commit/SKILL.md", gitCommitContent)
				stubInstallFiles(reg, "monalisa", "original-skills",
					"upTreeSHA", "upBlobSHA", gitCommitContent)
			},
			opts: func(t *testing.T, ios *iostreams.IOStreams, reg *httpmock.Registry) *InstallOptions {
				return &InstallOptions{
					IO:           ios,
					HttpClient:   func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
					GitClient:    &git.Client{RepoDir: t.TempDir()},
					Telemetry:    &telemetry.NoOpService{},
					SkillSource:  "monalisa/skills-repo",
					SkillName:    "git-commit",
					Agent:        "github-copilot",
					Scope:        "project",
					ScopeChanged: true,
					Dir:          t.TempDir(),
					Upstream:     true,
				}
			},
			wantStderr: "Redirecting install to monalisa/original-skills",
			wantStdout: "Installed git-commit",
		},
```
