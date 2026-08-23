### Title
Skill source ref can be front-run between `gh skill preview` and `gh skill install`, causing different content to be installed than what was reviewed - ([File: internal/skills/discovery/discovery.go])

### Summary
`gh skill preview` and `gh skill install` each independently call `discovery.ResolveRef` to turn an unpinned version string (or no version at all) into a commit SHA before fetching skill content. When no explicit version is supplied, `ResolveRef` resolves a *mutable* pointer — the latest release tag or the repository's default branch — rather than a fixed commit. [1](#0-0)  Because the user's review (`preview`) and the actual write-to-disk action (`install`) are two separate `gh` invocations that each re-resolve this mutable ref independently, the repository owner (an unprivileged remote party who merely needs to control the target skill repo) can serve benign content at preview time and swap in different content before the subsequent install resolves the ref again.

### Finding Description
`ResolveRef` prioritizes an explicit version, then falls back to the latest release tag, then to the default branch: [1](#0-0) . All three of the non-explicit paths (`resolveLatestRelease`, `resolveDefaultBranch`, and even branch/tag short-name resolution) resolve to whatever the ref currently points at on GitHub — a value fully controlled by the repository owner and changeable at any moment. [2](#0-1) 

`gh skill preview` calls `discovery.ResolveRef` and then fetches/display the skill's `SKILL.md` content for the user to audit before deciding to install: [3](#0-2) 

`gh skill install`, when run without an explicit pinned version, performs an entirely separate call to `discovery.ResolveRef` via `resolveVersion`: [4](#0-3) , and then discovers/writes the skill's files based on whatever SHA that second, independent resolution returns: [5](#0-4) 

This mirrors the structure of the reported Drips bug class: a verification/preview step is performed against state (`dripsHistoryHash` / a mutable git ref) that the untrusted counterparty (the drips sender / the skill-repo owner) can change before the second, dependent operation (squeeze / install) is executed, invalidating the assumption that the two steps observed the same state. Here, instead of causing denial-of-service, the attacker-controlled state change causes the install step to silently fetch and write different content than what the user reviewed in `preview` — undermining the entire purpose of `gh skill preview` as a pre-install audit mechanism. The written files (including scripts alongside `SKILL.md`, per `installSkill`) are later available for execution/consumption by AI agents. [6](#0-5) 

### Impact Explanation
A user following the documented safe workflow — review a skill with `gh skill preview owner/repo skill` before trusting it, then `gh skill install owner/repo skill` — has no guarantee that the content installed is the same content they reviewed, if they didn't pin an explicit ref/SHA. A malicious or compromised skill-repo owner can time a branch/tag update (or simply publish a new release) between the two commands to serve reviewed, benign content to `preview` and malicious content (e.g. malicious `SKILL.md` instructions or accompanying scripts) to `install`. Because installed skill content is designed to be consumed/acted upon by AI coding agents, this is a verification-bypass of the CLI's own pre-install review control, not merely a denial-of-service.

### Likelihood Explanation
The attacker only needs to control the timing of pushes/tag moves/releases on their own public repository — no privileged access to the victim's machine or GitHub account is required, matching the "unprivileged remote attacker publishing content" analog class. The likelihood is bounded by the fact that the user must (a) omit an explicit pinned version on both `preview` and `install`, and (b) run the two commands far enough apart in time for the attacker to swap content, which is a realistic but not universal usage pattern.

### Recommendation
When a user has just run `gh skill preview`, encourage/require pinning the resolved SHA for the subsequent `gh skill install` (the codebase already supports pinning via `--pin`/`PinnedRef`, and `install.go`'s `printReviewHint` prints a SHA-qualified preview command — but only *after* installing, not before). Consider: resolving the ref once and threading the same resolved SHA between `preview` and `install` when used interactively/in sequence, or defaulting `install` to require `--pin`/explicit SHA whenever it is invoked after (or in combination with) a `preview` in the same session, and clearly warning users that unpinned installs may not match previously previewed content.

### Proof of Concept
1. Attacker publishes `owner/skills-repo` with a benign `skills/demo/SKILL.md` at the current default branch HEAD (or latest release tag).
2. Victim runs `gh skill preview owner/skills-repo demo` (no version pinned) and reviews the benign content; `previewRun` resolves the ref via `discovery.ResolveRef` and shows the file. [3](#0-2) 
3. Attacker pushes new content to the same branch or moves the tag / cuts a new release with a malicious `SKILL.md` (and/or an additional malicious script file).
4. Victim, trusting the review, runs `gh skill install owner/skills-repo demo` (still unpinned). `resolveVersion` re-resolves the same mutable ref — now pointing at the attacker's new commit — and `installSkill` writes the new, unreviewed files to `$HOME/.copilot/skills/demo/` (or the configured agent skill directory) for later agent consumption. [7](#0-6) [6](#0-5)

### Citations

**File:** internal/skills/discovery/discovery.go (L205-224)
```go
// ResolveRef determines the git ref to use for a given owner/repo.
// Priority: explicit version > latest release tag > default branch.
func ResolveRef(client *api.Client, host, owner, repo, version string) (*ResolvedRef, error) {
	if version != "" {
		return resolveExplicitRef(client, host, owner, repo, version)
	}
	ref, err := resolveLatestRelease(client, host, owner, repo)
	if err == nil {
		return ref, nil
	}
	// Only fall back to the default branch when the repository genuinely
	// has no releases (404) or the latest release has no tag. Any other
	// API error (403, 500, network failure, …) is surfaced immediately
	// so it cannot silently mask problems and cause an unexpected ref to
	// be used.
	var nre *noReleasesError
	if !errors.As(err, &nre) {
		return nil, err
	}
	return resolveDefaultBranch(client, host, owner, repo)
```

**File:** internal/skills/discovery/discovery.go (L309-324)
```go
// resolveBranchRef looks up a branch by short name and returns a fully qualified ref.
func resolveBranchRef(client *api.Client, host, owner, repo, branch string) (*ResolvedRef, error) {
	refPath, err := safeurl.JoinPath("repos", owner, repo, "git", "ref", fmt.Sprintf("heads/%s", branch))
	if err != nil {
		return nil, err
	}
	var refResp struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := client.REST(host, "GET", refPath.String(), nil, &refResp); err != nil {
		return nil, fmt.Errorf("branch %q not found in %s/%s: %w", branch, owner, repo, err)
	}
	return &ResolvedRef{Ref: "refs/heads/" + branch, SHA: refResp.Object.SHA}, nil
}
```

**File:** pkg/cmd/skills/preview/preview.go (L158-212)
```go
	opts.IO.StartProgressIndicatorWithLabel(fmt.Sprintf("Resolving %s/%s", owner, repoName))
	resolved, err := discovery.ResolveRef(apiClient, hostname, owner, repoName, opts.Version)
	opts.IO.StopProgressIndicator()
	if err != nil {
		return fmt.Errorf("could not resolve version: %w", err)
	}

	var skill discovery.Skill
	if discovery.IsSkillPath(opts.SkillName) {
		opts.IO.StartProgressIndicatorWithLabel("Looking up skill")
		found, err := discovery.DiscoverSkillByPathWithOptions(apiClient, hostname, owner, repoName, resolved.SHA, opts.SkillName, discovery.DiscoverSkillByPathOptions{SkipDescription: true})
		opts.IO.StopProgressIndicator()
		if err != nil {
			return err
		}
		skill = *found
	} else {
		opts.IO.StartProgressIndicatorWithLabel("Discovering skills")
		allSkills, err := discovery.DiscoverSkillsWithOptions(apiClient, hostname, owner, repoName, resolved.SHA, discovery.DiscoverOptions{})
		opts.IO.StopProgressIndicator()
		if err != nil {
			return err
		}

		skills, err := filterHiddenDirSkills(opts, allSkills)
		if err != nil {
			return err
		}

		sort.Slice(skills, func(i, j int) bool {
			return skills[i].DisplayName() < skills[j].DisplayName()
		})

		skill, err = selectSkill(opts, skills)
		if err != nil {
			return err
		}
	}

	opts.IO.StartProgressIndicatorWithLabel("Fetching skill content")
	var files []discovery.SkillFile
	if skill.TreeSHA != "" {
		files, err = discovery.ListSkillFiles(apiClient, hostname, owner, repoName, skill.TreeSHA)
		if err != nil {
			fmt.Fprintf(opts.IO.ErrOut, "warning: could not list skill files: %v\n", err)
			files = nil
		}
	}
	content, err := discovery.FetchBlob(apiClient, hostname, owner, repoName, skill.BlobSHA)
	opts.IO.StopProgressIndicator()
	if err != nil {
		return err
	}

	rendered := opts.renderFile("SKILL.md", content.String())
```

**File:** pkg/cmd/skills/install/install.go (L623-657)
```go
func resolveVersion(opts *InstallOptions, client *api.Client, hostname string) (*discovery.ResolvedRef, error) {
	opts.IO.StartProgressIndicatorWithLabel("Resolving version")
	resolved, err := discovery.ResolveRef(client, hostname, opts.repo.RepoOwner(), opts.repo.RepoName(), opts.version)
	opts.IO.StopProgressIndicator()
	if err != nil {
		return nil, fmt.Errorf("could not resolve version: %w", err)
	}
	fmt.Fprintf(opts.IO.ErrOut, "Using ref %s (%s)\n", discovery.ShortRef(resolved.Ref), git.ShortSHA(resolved.SHA))
	return resolved, nil
}

func discoverSkills(opts *InstallOptions, client *api.Client, hostname string, resolved *discovery.ResolvedRef) ([]discovery.Skill, error) {
	opts.IO.StartProgressIndicatorWithLabel("Discovering skills")
	allSkills, err := discovery.DiscoverSkillsWithOptions(client, hostname, opts.repo.RepoOwner(), opts.repo.RepoName(), resolved.SHA, discovery.DiscoverOptions{})
	opts.IO.StopProgressIndicator()
	if err != nil {
		var treeTooLarge *discovery.TreeTooLargeError
		if errors.As(err, &treeTooLarge) {
			fmt.Fprintf(opts.IO.ErrOut, "%s\n  Use path-based install instead: gh skill install %s/%s skills/<skill-name>\n",
				err, treeTooLarge.Owner, treeTooLarge.Repo)
			return nil, err
		}
		return nil, err
	}
	skills, filterErr := filterHiddenDirSkills(opts, allSkills)
	if filterErr != nil {
		return nil, filterErr
	}
	logConventions(opts.IO, skills)
	for _, s := range skills {
		if !discovery.IsSpecCompliant(s.Name) {
			fmt.Fprintf(opts.IO.ErrOut, "Warning: skill %q does not follow the agentskills.io naming convention\n", s.DisplayName())
		}
	}
	return skills, nil
```

**File:** internal/skills/installer/installer.go (L251-306)
```go
func installSkill(opts *Options, skill discovery.Skill, baseDir string) error {
	// Use skill.Name (not InstallName) for a flat directory layout.
	skillDir := filepath.Join(baseDir, skill.Name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return fmt.Errorf("could not create directory %s: %w", skillDir, err)
	}

	files, err := discovery.DiscoverSkillFiles(opts.Client, opts.Host, opts.Owner, opts.Repo, skill.TreeSHA, skill.Path)
	if err != nil {
		return fmt.Errorf("could not list skill files: %w", err)
	}

	safeSkillDir, err := safepaths.ParseAbsolute(skillDir)
	if err != nil {
		return fmt.Errorf("could not resolve skill directory path: %w", err)
	}

	for _, file := range files {
		fetchedContent, err := discovery.FetchBlob(opts.Client, opts.Host, opts.Owner, opts.Repo, file.SHA)
		if err != nil {
			return fmt.Errorf("could not fetch %s: %w", file.Path, err)
		}

		// Install path: the blob is written to disk verbatim, so the raw bytes
		// must be preserved.
		content := fetchedContent.Raw()

		relPath := strings.TrimPrefix(file.Path, skill.Path+"/")

		safeDest, err := safeSkillDir.Join(relPath)
		if err != nil {
			var traversalErr safepaths.PathTraversalError
			if errors.As(err, &traversalErr) {
				return fmt.Errorf("blocked path traversal in %q", relPath)
			}
			return fmt.Errorf("could not resolve destination path: %w", err)
		}
		destPath := safeDest.String()

		if dir := filepath.Dir(destPath); dir != skillDir {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("could not create directory: %w", err)
			}
		}

		if filepath.Base(relPath) == "SKILL.md" {
			content, err = frontmatter.InjectGitHubMetadata(content, opts.Host, opts.Owner, opts.Repo, opts.Ref, skill.TreeSHA, opts.PinnedRef, skill.Path)
			if err != nil {
				return fmt.Errorf("could not inject metadata: %w", err)
			}
		}

		if err := os.WriteFile(destPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("could not write %s: %w", destPath, err)
		}
	}
```
