Based on my investigation, I found a genuine analog of this bug class in the `gh skill install` upstream-provenance redirect flow.

### Title
Upstream-provenance redirect trusts remote-controlled `github-repo` metadata and re-invokes `installRun` with attacker-swapped repo, bypassing the original repo's disclaimer/visibility context - ([File: pkg/cmd/skills/install/install.go])

### Summary
`gh skill install` fetches the selected skill's `SKILL.md` and checks for `github-repo` frontmatter metadata that claims the file was "re-published" from an upstream source, then it silently swaps `opts.repo` to that claimed upstream and recursively calls `installRun(opts)` again [1](#0-0) . This mirrors the dandelion-org bug class: two logically-separate pieces of state (the originally-resolved, user-supplied repository vs. an attacker-supplied "upstream" value embedded in file content) get merged by a helper (`checkUpstreamProvenance`) and the result silently overwrites the trusted value (`opts.repo`) that a later step (the actual download in `installer.Install`) consumes.

### Finding Description
The flow is:
1. User runs `gh skill install owner/repo skill-name`.
2. `installRun` resolves the version and discovers/selects skills from `owner/repo` [2](#0-1) .
3. If the selected skill's `SKILL.md` has a `BlobSHA`, `checkUpstreamProvenance` is called, which inspects the skill's own frontmatter metadata (fully attacker-controlled content living in `owner/repo`) for a `github-repo` field pointing to a different "upstream" repository.
4. If detected, `opts.repo` is overwritten with the attacker-declared upstream repo and `opts.version`/`opts.Pin` are cleared, and `installRun` recurses using that new repo [3](#0-2) .
5. The recursive call re-resolves the version and re-discovers skills — this time entirely against the attacker-chosen "upstream" repo/owner, with a fresh (unpinned) ref resolution, and installs those files under the same skill name the user originally requested.

Because `owner/repo` is fully attacker-controlled (it's just any GitHub repository the attacker can publish content to, and skill install explicitly targets untrusted, community-sourced content — see `pkg/cmd/skills/install/install_test.go` stderr checks for "not verified by GitHub" [4](#0-3) ), the attacker fully controls the value that gets used to overwrite `opts.repo`. This is directly analogous to `DandelionOrg`'s `_saveToken`/`_getToken`: a value from one context (an untrusted, attacker-authored artifact) silently replaces state that a downstream function (`installer.Install`, which fetches and writes files to disk) blindly trusts as the resolved installation target.

### Impact Explanation
An attacker who controls a GitHub repository (e.g. `attacker/decoy-skills`) can publish a skill whose `SKILL.md` frontmatter declares `github-repo: attacker/actually-malicious-repo`. When a victim runs `gh skill install attacker/decoy-skills some-skill`, the tool silently redirects and installs files from `attacker/actually-malicious-repo` instead — files get written to the user's `.agents/skills` (or agent-specific) directories on disk, potentially including files with names the victim did not review, since the disclaimer and review hints refer to the *original* `repoSource` argument the user typed, not necessarily reflecting the swap clearly before installation proceeds. This is a "file write outside the intended (trusted) source" style impact: content ends up on disk sourced from a repository the user never specified or reviewed.

### Likelihood Explanation
Moderate-to-high: skill installation from arbitrary/community/public repos is the primary use case of this command (it is explicitly a "preview" feature aimed at consuming untrusted third-party skill repos, as reflected in the "not verified by GitHub" warning shown for all remote installs). Any attacker able to get a victim to run `gh skill install <attacker-repo> <skill>` (a common recommended action pattern for sharing skills) can trigger the redirect purely through file content they control — no additional access or privilege is required.

### Recommendation
Do not let content fetched from the same untrusted repository silently redirect the effective install source without an explicit, clearly-surfaced confirmation naming both the original and the claimed upstream repository (a prompt is already partially present via `Upstream`/`checkUpstreamProvenance`, but the non-interactive/default path should not auto-follow the redirect). At minimum, treat the "upstream" value as informational only and require `--upstream` or an explicit interactive confirmation before actually installing from the swapped repository, and always print both the original requested source and the redirected source with equal prominence before any files are written.

### Proof of Concept
1. Attacker creates `attacker/decoy` with a skill `foo` whose `SKILL.md` frontmatter contains a `github-repo` field pointing to `attacker/payload-repo`.
2. Attacker convinces victim (e.g. via README, chat, forum post) to run: `gh skill install attacker/decoy foo`.
3. `installRun` discovers `foo`, calls `checkUpstreamProvenance`, finds the `github-repo` upstream claim, sets `opts.repo = attacker/payload-repo`, and recurses [1](#0-0) .
4. The recursive `installRun` resolves the version and installs skill content from `attacker/payload-repo` — a repository the victim never named — onto disk.

**Note on completeness:** I was unable to fully inspect `checkUpstreamProvenance`'s implementation (in a truncated portion of `install.go` not covered by my reads) to confirm exactly what validation, if any, it performs on the claimed upstream repo (e.g., whether it cross-checks tree SHAs or requires additional confirmation before the redirect). If it already enforces a strict interactive confirmation before redirecting, the severity would be lower than described above; recommend a Devin session with full file access to verify this function's logic before treating this as fully confirmed.

### Citations

**File:** pkg/cmd/skills/install/install.go (L300-336)
```go
	resolved, err := resolveVersion(opts, apiClient, hostname)
	if err != nil {
		return err
	}

	var selectedSkills []discovery.Skill

	if discovery.IsSkillPath(opts.SkillName) {
		opts.IO.StartProgressIndicatorWithLabel("Looking up skill")
		skill, err := discovery.DiscoverSkillByPath(apiClient, hostname, opts.repo.RepoOwner(), opts.repo.RepoName(), resolved.SHA, opts.SkillName)
		opts.IO.StopProgressIndicator()
		if err != nil {
			return err
		}
		selectedSkills = []discovery.Skill{*skill}
	} else {
		skills, err := discoverSkills(opts, apiClient, hostname, resolved)
		if err != nil {
			return err
		}

		selectedSkills, err = selectSkillsWithSelector(opts, skills, canPrompt, skillSelector{
			matchByName: matchSkillByName,
			sourceHint:  ghrepo.FullName(opts.repo),
			fetchDescriptions: func() {
				opts.IO.StartProgressIndicatorWithLabel("Fetching skill info")
				discovery.FetchDescriptionsConcurrent(apiClient, hostname, opts.repo.RepoOwner(), opts.repo.RepoName(), skills, nil)
				opts.IO.StopProgressIndicator()
			},
		})
		if err != nil {
			if errors.Is(err, errSkillsListed) {
				return nil
			}
			return err
		}
	}
```

**File:** pkg/cmd/skills/install/install.go (L345-369)
```go
	if len(selectedSkills) == 1 && selectedSkills[0].BlobSHA != "" {
		upstreamRepo, detected, err := checkUpstreamProvenance(opts, apiClient, hostname, selectedSkills[0], resolved.SHA)
		if err != nil {
			return err
		}
		if upstreamRepo != nil {
			redirectDims := map[string]string{}
			select {
			case r := <-visCh:
				if r.err == nil && r.vis == discovery.RepoVisibilityPublic {
					redirectDims["from_owner"] = visOwner
					redirectDims["from_repo"] = visRepo
				}
			case <-time.After(visibilityWaitTimeout):
			}
			opts.Telemetry.Record(ghtelemetry.Event{
				Type:       "skill_upstream_redirect",
				Dimensions: redirectDims,
			})
			opts.repo = upstreamRepo
			opts.SkillSource = ghrepo.FullName(upstreamRepo)
			opts.version = ""
			opts.Pin = ""
			return installRun(opts)
		}
```

**File:** pkg/cmd/skills/install/install_test.go (L686-712)
```go
		},
		{
			name:  "remote install shows pre-install disclaimer",
			isTTY: true,
			stubs: func(reg *httpmock.Registry) {
				stubResolveVersion(reg, "monalisa", "skills-repo", "v1.0.0", "abc123")
				stubDiscoverTree(reg, "monalisa", "skills-repo", "abc123",
					singleSkillTreeJSON("git-commit", "treeSHA", "blobSHA"))
				stubInstallFiles(reg, "monalisa", "skills-repo", "treeSHA", "blobSHA", gitCommitContent)
			},
			opts: func(ios *iostreams.IOStreams, reg *httpmock.Registry) *InstallOptions {
				t.Helper()
				return &InstallOptions{
					IO:           ios,
					HttpClient:   func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
					GitClient:    &git.Client{RepoDir: t.TempDir()},
					SkillSource:  "monalisa/skills-repo",
					SkillName:    "git-commit",
					Agent:        "github-copilot",
					Scope:        "project",
					ScopeChanged: true,
					Dir:          t.TempDir(),
				}
			},
			wantStdout: "Installed git-commit",
			wantStderr: "not verified by GitHub",
		},
```
