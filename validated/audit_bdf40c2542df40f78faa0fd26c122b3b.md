### Title
`gh skill update` re-trusts source repositories by mutable `owner/repo` name with no persistent-identity binding, enabling repo-jacking-style trap installs of attacker content - (File: `pkg/cmd/skills/update/update.go`, `internal/skills/frontmatter/frontmatter.go`, `internal/skills/source/source.go`)

### Summary
The Cally report's root cause is that trust was bound to a *cheap, reusable identifier* (a token contract address) instead of to the actual entity, so an attacker could pre-stake a claim on that identifier and profit once a legitimate deployer later took over the identifier. `gh skill`'s update/tracking system has the same structural weakness: once a skill is installed, `gh` stores only `github-repo: https://github.com/<owner>/<repo>` (a plain string) in the skill's frontmatter as its source-of-truth for all future `gh skill update` operations. There is no persistent, non-reassignable identifier (e.g. a GitHub repository node ID) recorded or checked.

### Finding Description
When a skill is installed, `installSkill`/`installLocalSkill` write GitHub tracking metadata into `SKILL.md` via `frontmatter.InjectGitHubMetadata`, which just serializes `host`, `owner`, `repo` (as a URL string) and a tree SHA: [1](#0-0) 

Later, `gh skill update` re-derives the trusted source purely from that stored string via `source.ParseMetadataRepo`, which just parses `owner/repo` out of the URL - no repository ID, no continuity check: [2](#0-1) 

`updateRun` then uses only `(host, owner, repo)` to resolve the latest ref and enumerate skills from whatever repository currently exists at that path: [3](#0-2) 

If new content differs by tree SHA (or `--force` is passed), `updateSkillInPlace` calls the installer to fetch files from that `owner/repo` and atomically swap them into the user's local skill directory - again addressed only by owner/repo, never validated against the repository that was originally installed from: [4](#0-3) 

Because GitHub repository names/ownership are mutable (a repo can be deleted, renamed, transferred, or an org/user account can be deleted and re-registered by someone else — the well-known "repo-jacking" pattern), an attacker can:
1. Wait for (or induce) an `owner/repo` slot used by a legitimate skill source to become free, and claim it, publishing a malicious `SKILL.md` (and any scripts referenced by it, since the skill install flow writes arbitrary files including `scripts/*.sh` to disk, as seen in `skills-publish-lifecycle.txtar`).
2. Any user who previously installed the legitimate skill (metadata pointing at that same `owner/repo` string) and later runs `gh skill update --all` (a documented, encouraged workflow — see `SKILL.md`'s "Self-management pattern for agents": "Periodically `gh skill update --all` to refresh") will have the attacker's content silently downloaded and written over the local skill files, with no indication that the underlying repository identity changed.
3. `gh skill update` in non-interactive/`--all` mode requires no user confirmation of *source* identity — only a generic "Update N skill(s)?" confirmation — and the installed content can include scripts that agents (Copilot, Claude, etc.) are told to "run" per the "Self-management pattern" in the skill.

This mirrors the Cally bug class precisely: trust is anchored to a cheap, attacker-claimable identifier (`owner/repo` string / ERC20 address) rather than to a durable, non-transferable identity, so an attacker can pre-position content at an identifier now and have it silently activate against legitimate users' future actions once that identifier is captured.

### Impact Explanation
A successful repo-jacking of a skill's source repository results in `gh skill update` writing attacker-controlled files (including executable scripts referenced from `SKILL.md`) into the user's or project's skill directory without any warning that the source has changed ownership. Since Agent Skills are explicitly designed to be read and acted upon by AI coding agents (the `SKILL.md` documents instruct agents to "run the setup script"), this can lead to arbitrary command execution in the victim's environment once an agent processes the tainted skill, or at minimum a supply-chain-style file-write outside of any expected/pinned content.

### Likelihood Explanation
This requires an actual GitHub-level repo-jacking condition (i.e., the original `owner/repo` becoming available for the attacker to claim), so it is not exploitable at will against an arbitrary target the way the Cally PoC's pure ERC20 pre-registration is. It is, however, a well-documented and previously observed real-world attack class (GitHub repo-jacking / dependency confusion via abandoned/renamed repos), and `gh skill update --all` is explicitly recommended as a periodic, unattended workflow for agents, which increases realistic exposure. `--pin` mitigates this (pinned skills are skipped from updates), but pinning is optional and not the default.

### Recommendation
- Store and verify a durable repository identifier (e.g. GraphQL `node_id`/`databaseId`) alongside `owner/repo` in the injected metadata, and refuse (or warn loudly and require explicit confirmation) if `gh skill update` detects that the repository behind a previously trusted `owner/repo` now resolves to a different underlying repository ID.
- Surface an explicit "source repository identity changed" warning during `updateRun` when the resolved repo's ID doesn't match what was recorded at install time, rather than silently overwriting content.
- Encourage/steer users toward `--pin` for repositories they rely on being stable, and consider treating repository identity changes the same way `git` treats unexpected remote SSH host-key changes (hard failure requiring explicit override).

### Proof of Concept
1. Alice runs `gh skill install trusted-org/skills-repo cool-skill --scope user`. The installed `SKILL.md` records `metadata.github-repo: https://github.com/trusted-org/skills-repo` and a `github-tree-sha`.
2. `trusted-org` deletes or transfers the `skills-repo` repository (or the org account itself becomes available), and an attacker registers a repository at the exact same `trusted-org/skills-repo` path, publishing a `cool-skill/SKILL.md` with a malicious `scripts/setup.sh`.
3. Alice later runs `gh skill update --all` (a workflow explicitly recommended in the skill's own `SKILL.md` "Self-management pattern for agents" section). `updateRun` resolves `trusted-org/skills-repo` purely by name via `discovery.ResolveRef`/`discovery.DiscoverSkills`, sees a different tree SHA, and calls `updateSkillInPlace`, which fetches and writes the attacker's files into Alice's skill directory with no warning that the underlying repository is no longer the one originally trusted.
4. If Alice's coding agent later "runs the setup script" per the skill's own instructions, the attacker achieves code execution in Alice's environment.

Note: I was not able to fully verify whether any repository-ID cross-check exists elsewhere in the discovery/installer pipeline beyond what's shown above (e.g., in `internal/skills/discovery/discovery.go`, which only appeared as a single incidental match for repository-ID-related terms); a Devin session with full repo access would be needed to confirm there is no such check anywhere in that package before treating this as fully conclusive.

### Citations

**File:** internal/skills/frontmatter/frontmatter.go (L70-98)
```go
func InjectGitHubMetadata(content string, host, owner, repo, ref, treeSHA, pinnedRef, skillPath string) (string, error) {
	result, err := Parse(content)
	if err != nil {
		return "", err
	}

	if result.RawYAML == nil {
		result.RawYAML = make(map[string]interface{})
	}

	meta, _ := result.RawYAML["metadata"].(map[string]interface{})
	if meta == nil {
		meta = make(map[string]interface{})
	}
	delete(meta, "github-owner")
	meta["github-repo"] = source.BuildRepoURL(host, owner, repo)
	meta["github-ref"] = ref
	delete(meta, "github-sha")
	meta["github-tree-sha"] = treeSHA
	meta["github-path"] = skillPath
	if pinnedRef != "" {
		meta["github-pinned"] = pinnedRef
	} else {
		delete(meta, "github-pinned")
	}
	result.RawYAML["metadata"] = meta

	return Serialize(result.RawYAML, result.Body)
}
```

**File:** internal/skills/source/source.go (L34-51)
```go
// ParseMetadataRepo extracts repository information from skill metadata.
func ParseMetadataRepo(meta map[string]interface{}) (ghrepo.Interface, bool, error) {
	if meta == nil {
		return nil, false, nil
	}

	repoValue, _ := meta["github-repo"].(string)
	if repoValue == "" {
		return nil, false, nil
	}

	repo, err := ParseRepoURL(repoValue)
	if err != nil {
		return nil, true, err
	}

	return repo, true, nil
}
```

**File:** pkg/cmd/skills/update/update.go (L266-292)
```go
		key := repoKey{s.repoHost, s.owner, s.repo}

		if repoErrors[key] {
			continue
		}

		// Resolve ref and discover skills once per repo
		if _, ok := repoRefs[key]; !ok {
			resolved, resolveErr := discovery.ResolveRef(apiClient, s.repoHost, s.owner, s.repo, "")
			if resolveErr != nil {
				repoErrors[key] = true
				opts.IO.StopProgressIndicator()
				fmt.Fprintf(opts.IO.ErrOut, "%s Skipping %s: could not resolve %s/%s: %v\n", cs.WarningIcon(), s.name, s.owner, s.repo, resolveErr)
				opts.IO.StartProgressIndicatorWithLabel(fmt.Sprintf("Checking %d installed skill(s) for updates", len(installed)))
				continue
			}
			repoRefs[key] = resolved

			skills, discoverErr := discovery.DiscoverSkills(apiClient, s.repoHost, s.owner, s.repo, resolved.SHA)
			if discoverErr != nil {
				repoErrors[key] = true
				opts.IO.StopProgressIndicator()
				fmt.Fprintf(opts.IO.ErrOut, "%s Skipping %s: %v\n", cs.WarningIcon(), s.name, discoverErr)
				opts.IO.StartProgressIndicatorWithLabel(fmt.Sprintf("Checking %d installed skill(s) for updates", len(installed)))
				continue
			}
			repoSkills[key] = skills
```

**File:** pkg/cmd/skills/update/update.go (L418-450)
```go
func updateSkillInPlace(opts *UpdateOptions, u pendingUpdate, apiClient *api.Client, gitRoot, homeDir string) error {
	if u.local.dir == "" {
		return fmt.Errorf("cannot update %s: no install location recorded", u.local.name)
	}

	parent := filepath.Dir(u.local.dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("could not ensure parent directory %s: %w", parent, err)
	}

	// Stage as a sibling of the existing skill directory so the swap stays
	// on the same filesystem and every rename is atomic.
	staging, err := os.MkdirTemp(parent, "."+u.skill.Name+".gh-skill-update-")
	if err != nil {
		return fmt.Errorf("could not create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	installOpts := &installer.Options{
		Host:    u.local.repoHost,
		Owner:   u.local.owner,
		Repo:    u.local.repo,
		Ref:     u.resolved.Ref,
		SHA:     u.resolved.SHA,
		Skills:  []discovery.Skill{u.skill},
		Dir:     staging,
		GitRoot: gitRoot,
		HomeDir: homeDir,
		Client:  apiClient,
	}
	if _, err := installer.Install(installOpts); err != nil {
		return err
	}
```
