### Title
Unverified, self-declared `github-repo` provenance metadata lets any repo publisher spoof "upstream" origin and redirect `gh skill install` to an attacker-chosen source - ([File: pkg/cmd/skills/install/install.go])

### Summary
`gh skill install` implements a "republish detection" feature (`checkUpstreamProvenance`) that reads a `github-repo` field from the target skill's `SKILL.md` frontmatter and, if it differs from the repo the user asked to install from, tells the user the skill was "originally published" elsewhere and offers (or, with `--upstream`, automatically performs) a redirect to install from that other repository instead. The `github-repo` value is taken as-is from content the repo owner controls, with no proof that it is genuine. Any unprivileged GitHub user who can publish a repository with a skill can forge this field, similar to how the TribeRedeemer contract's "sufficient balance" check could be trivially satisfied by anyone transferring a token, defeating a safety heuristic that users implicitly trust.

### Finding Description
`checkUpstreamProvenance` fetches `SKILL.md` from the repo the user is installing from via the contents API, parses its frontmatter, and reads the `metadata.github-repo` key: [1](#0-0) 

If that value differs from the current repo URL, it is parsed straight into a `ghrepo.Interface` and treated as a legitimate "upstream" location: [2](#0-1) 

Nothing verifies that the declared upstream repo actually published this skill, that it is the same skill, or that the claimant has any relationship to it. This metadata is normally *written by gh itself* on install (as documented in the acceptance test, which asserts the injected `github-repo`/`github-tree-sha` frontmatter): [3](#0-2) 

But `checkUpstreamProvenance` re-reads this field directly from the untrusted repo content rather than from any independently-verifiable provenance channel, so an attacker can hand-write the same frontmatter shape in their own repository, pointing `github-repo` at any owner/repo they choose (including another attacker-controlled repo, or a well-known legitimate org's repo whose name they simply reuse for social-engineering purposes).

The redirect path is reached from the normal `installRun` flow whenever a single skill is selected, with no special conditions required from the victim beyond running the plain command: [4](#0-3) 

If the user runs non-interactively with `--upstream` (a flag explicitly documented as "install from the upstream source when a re-published skill is detected"), the tool trusts the forged pointer and silently re-runs the whole install against the attacker-chosen repository: [5](#0-4) 

### Impact Explanation
A user who trusts the "recommended" upstream-redirect UX (or scripts installs with `--upstream` to always prefer the canonical source) can be silently redirected to install and execute skill content from a repository the attacker nominates, not the repository they explicitly named on the command line. Because installed skills are files consumed by AI agent tooling, this is a supply-chain integrity issue: the tool's own anti-republish heuristic becomes an attacker-controlled redirection primitive. This mirrors the TribeRedeemer pattern where a state-based trust signal (non-zero balance / here, a self-declared provenance field) is meant to gate a decision but can be forged by any unprivileged actor at negligible cost.

### Likelihood Explanation
Exploitation only requires publishing a public GitHub repository containing a skill whose `SKILL.md` has hand-crafted frontmatter — no elevated privileges, no compromise of any existing repo, and no interaction beyond a victim running `gh skill install <attacker-repo> <skill>` and either accepting the interactive "upstream" prompt or already using `--upstream`. This is comparable in cost/likelihood to the original finding's "send a small token amount to the contract."

### Recommendation
Do not treat self-declared `github-repo` metadata inside installable content as authoritative provenance. At minimum:
- Require explicit, unambiguous user confirmation of the *destination* repo/owner before any redirect, rather than a generic "(upstream)" label based on unverified metadata.
- Independently corroborate the claim (e.g., only honor `github-repo` if the target repo's own lockfile-equivalent history or attestation confirms the relationship), or drop the automatic-redirect behavior for `--upstream` in non-interactive mode.
- Clearly warn that this "originally published in X" signal is unauthenticated content supplied by the repo being installed from.

### Proof of Concept
1. Attacker creates public repo `attacker/looks-legit` containing `skills/git-commit/SKILL.md` with frontmatter:
```yaml
---
name: git-commit
description: Writes commits
metadata:
  github-repo: https://github.com/attacker/evil-upstream
  github-tree-sha: fakeSHA
---
```
2. Victim runs `gh skill install attacker/looks-legit git-commit --upstream` (or accepts the interactive "upstream" choice), matching the exact code path exercised by `TestInstallRun_UpstreamDetection` in [6](#0-5) .
3. `checkUpstreamProvenance` reads the forged `github-repo` value and `installRun` re-invokes itself against `attacker/evil-upstream`, installing content from a repository the victim never named.

### Citations

**File:** pkg/cmd/skills/install/install.go (L338-369)
```go
	// Track upstream provenance detection result for telemetry.
	upstreamSource := "none"

	// Check if the selected skill was re-published from an upstream source.
	// The re-publisher's SKILL.md will have github-repo metadata pointing
	// to the original source repo. If detected, offer to install directly
	// from upstream instead.
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

**File:** pkg/cmd/skills/install/install.go (L1299-1336)
```go
func checkUpstreamProvenance(opts *InstallOptions, client *api.Client, hostname string, skill discovery.Skill, commitSHA string) (ghrepo.Interface, bool, error) {
	u, err := safeurl.JoinPath("repos", opts.repo.RepoOwner(), opts.repo.RepoName(), "contents", skill.Path+"/SKILL.md")
	if err != nil {
		return nil, false, err
	}
	u.SetQuery("ref", commitSHA)
	var fileResp struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := client.REST(hostname, "GET", u.String(), nil, &fileResp); err != nil {
		return nil, false, nil //nolint:nilerr // best-effort check; failing to fetch is not fatal
	}
	if fileResp.Encoding != "base64" {
		return nil, false, nil
	}
	decoded, decodeErr := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(fileResp.Content)))
	if decodeErr != nil {
		return nil, false, nil //nolint:nilerr // best-effort; decode failure is not fatal
	}
	content := string(decoded)

	result, parseErr := frontmatter.Parse(content)
	if parseErr != nil || result.Metadata.Meta == nil {
		//nolint:nilerr // unparsable frontmatter means no upstream to detect
		return nil, false, nil
	}

	existingRepo, _ := result.Metadata.Meta["github-repo"].(string)
	if existingRepo == "" {
		return nil, false, nil
	}

	currentRepoURL := source.BuildRepoURL(hostname, opts.repo.RepoOwner(), opts.repo.RepoName())
	if existingRepo == currentRepoURL {
		return nil, false, nil
	}

```

**File:** pkg/cmd/skills/install/install.go (L1337-1352)
```go
	upstreamRepo, parseErr := source.ParseRepoURL(existingRepo)
	if parseErr != nil {
		//nolint:nilerr // invalid repo URL means we can't redirect; install normally
		return nil, false, nil
	}

	cs := opts.IO.ColorScheme()
	upstreamLabel := ghrepo.FullName(upstreamRepo)
	repoSource := ghrepo.FullName(opts.repo)

	fmt.Fprintf(opts.IO.ErrOut, "%s This skill was originally published in %s\n", cs.WarningIcon(), upstreamLabel)

	if opts.Upstream {
		fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
		return upstreamRepo, true, nil
	}
```

**File:** acceptance/testdata/skills/skills-install.txtar (L5-8)
```text
# Verify SKILL.md has frontmatter metadata injected
exists $HOME/.copilot/skills/git-commit/SKILL.md
grep 'github-repo' $HOME/.copilot/skills/git-commit/SKILL.md
grep 'github-tree-sha' $HOME/.copilot/skills/git-commit/SKILL.md
```

**File:** pkg/cmd/skills/install/install_test.go (L2724-2812)
```go
func TestInstallRun_UpstreamDetection(t *testing.T) {
	tests := []struct {
		name       string
		isTTY      bool
		stubs      func(*httpmock.Registry)
		opts       func(t *testing.T, ios *iostreams.IOStreams, reg *httpmock.Registry) *InstallOptions
		wantErr    string
		wantStdout string
		wantStderr string
	}{
		{
			name:  "detects re-published skill and user picks re-publisher",
			isTTY: true,
			stubs: func(reg *httpmock.Registry) {
				stubResolveVersion(reg, "monalisa", "skills-repo", "v1.0.0", "abc123")
				stubDiscoverTree(reg, "monalisa", "skills-repo", "abc123",
					singleSkillTreeJSON("git-commit", "treeSHA", "blobSHA"))
				stubContentsAPI(reg, "monalisa", "skills-repo",
					"skills/git-commit/SKILL.md", republishedContent)
				stubInstallFiles(reg, "monalisa", "skills-repo",
					"treeSHA", "blobSHA", republishedContent)
			},
			opts: func(t *testing.T, ios *iostreams.IOStreams, reg *httpmock.Registry) *InstallOptions {
				return &InstallOptions{
					IO:         ios,
					HttpClient: func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
					GitClient:  &git.Client{RepoDir: t.TempDir()},
					Prompter: &prompter.PrompterMock{
						SelectFunc: func(_ string, _ string, choices []string) (int, error) {
							require.Len(t, choices, 2)
							assert.Contains(t, choices[0], "monalisa/skills-repo")
							assert.Contains(t, choices[1], "monalisa/original-skills")
							return 0, nil
						},
					},
					Telemetry:    &telemetry.NoOpService{},
					SkillSource:  "monalisa/skills-repo",
					SkillName:    "git-commit",
					Agent:        "github-copilot",
					Scope:        "project",
					ScopeChanged: true,
					Dir:          t.TempDir(),
				}
			},
			wantStderr: "originally published in monalisa/original-skills",
			wantStdout: "Installed git-commit",
		},
		{
			name:  "detects re-published skill and user picks upstream",
			isTTY: true,
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
					IO:         ios,
					HttpClient: func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
					GitClient:  &git.Client{RepoDir: t.TempDir()},
					Prompter: &prompter.PrompterMock{
						SelectFunc: func(_ string, _ string, choices []string) (int, error) {
							require.Len(t, choices, 2)
							assert.Contains(t, choices[0], "monalisa/skills-repo")
							assert.Contains(t, choices[1], "monalisa/original-skills")
							return 1, nil
						},
					},
					Telemetry:    &telemetry.NoOpService{},
					SkillSource:  "monalisa/skills-repo",
					SkillName:    "git-commit",
					Agent:        "github-copilot",
					Scope:        "project",
					ScopeChanged: true,
					Dir:          t.TempDir(),
				}
			},
			wantStderr: "Redirecting install to monalisa/original-skills",
			wantStdout: "Installed git-commit",
		},
```
