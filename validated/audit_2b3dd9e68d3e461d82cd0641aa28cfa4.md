### Title
Skill `--upstream` provenance redirect trusts unauthenticated repository metadata embedded in the skill being installed, letting a remote attacker redirect installs to an arbitrary repository - (File: pkg/cmd/skills/install/install.go)

### Summary
`gh skill install` supports an "upstream provenance" feature: if the repository a user names on the command line ("re-publisher") contains a `SKILL.md` whose frontmatter claims the content was copied from a different `github-repo`, the CLI can redirect the entire install operation to that other, attacker-named repository. The redirect target is taken verbatim from content fetched from the repo the user is installing, i.e., from data the publisher of that very skill controls, with no cross-verification that the claimed "upstream" repo is authentic.

### Finding Description
In `checkUpstreamProvenance` [1](#0-0) , the CLI fetches `SKILL.md` for the skill being installed and parses its YAML frontmatter for a `github-repo` key:

```go
existingRepo, _ := result.Metadata.Meta["github-repo"].(string)
...
upstreamRepo, parseErr := source.ParseRepoURL(existingRepo)
```

This value comes entirely from the repository the user is already installing from (the "re-publisher"), which is fully attacker-controlled content (any public GitHub repo owner can put arbitrary text in `metadata.github-repo`). There is no verification that the named upstream repository actually published the original skill (e.g. no signature, no cross-check that the upstream repo's tree/blob SHA matches, no ownership verification).

If `--upstream` is passed (documented as a normal user-facing flag: "Install from the upstream source when a re-published skill is detected", also offered interactively via a prompt), the CLI redirects the entire install target:

```go
if opts.Upstream {
    fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
    return upstreamRepo, true, nil
}
```

Back in `installRun`, this repo swap is applied and the whole install is restarted against the attacker-chosen repo, with any pin/version state cleared and revalidated:

```go
opts.repo = upstreamRepo
opts.SkillSource = ghrepo.FullName(upstreamRepo)
opts.version = ""
opts.Pin = ""
return installRun(opts)
``` [2](#0-1) 

The redirected install then re-runs `resolveVersion`, `discoverSkills`/`DiscoverSkillByPath`, and ultimately `installer.Install`, which writes files fetched from the (now attacker-chosen) repository to disk under the user's agent skill directories [3](#0-2) , including injecting metadata that will be trusted on future `gh skill update` runs.

The interactive path presents the redirect as a recommended/likely-safer choice ("(upstream)"), and the non-interactive path explicitly documents `--upstream` as a way to prefer this redirected source [4](#0-3) . In both cases, the decision of "where do the installed files actually come from" is made using metadata supplied by the same untrusted party whose content is being installed — the same class of bug as the referenced report: an action (here, choosing the install source and finalizing the write-to-disk) is performed based on state (the "true" origin) that was fetched from, and can be freely set by, the party the check is nominally trying to route around.

### Impact Explanation
An attacker who controls (or contributes a skill to) a public GitHub repository can:
1. Publish a plausible/attractive skill in a repo a victim might reasonably choose to install from (e.g. a fork, mirror, or "awesome-skills" style aggregator).
2. Set `metadata.github-repo` in that skill's `SKILL.md` frontmatter to point at a second attacker-controlled repository.
3. If the victim runs `gh skill install <republisher-repo> <skill> --upstream` (a documented, unprivileged, ordinary CLI flag) or interactively selects the "(upstream)" option when prompted, the CLI silently installs content from the second, attacker-controlled repository instead of the repository the user explicitly named.

Since installed skills are files (SKILL.md, scripts, etc.) that are later consumed/read by AI coding agents (Copilot CLI, Claude Code, Cursor, etc.), this is effectively an attacker-directed content-supply redirection into the agent's skill directory — the file content and its provenance metadata are entirely attacker-chosen, undermining the very provenance feature meant to protect users.

### Likelihood Explanation
Requires the victim to explicitly use `--upstream` or accept the interactive "(upstream)" prompt, so it is not a fully silent 0-click bug, but the feature is presented as the *safer*/*recommended-sounding* choice ("originally published in X... Redirecting install to X") and is a normal, documented, unprivileged flag with no special trust prerequisites for the attacker (any public repo owner can trigger this).

### Recommendation
Do not trust the `github-repo` frontmatter field as an install-target selector by itself. At minimum:
- Require independent corroboration before redirecting (e.g., cross-check that the claimed upstream repo's current tree actually contains an identical skill with matching content/hash, not just that the re-publisher's copy claims to be sourced from there).
- Make the redirect strictly opt-in per-invocation with an explicit confirmation showing both repos and a clear warning that the target is attacker-supplied, rather than auto-labelling it "(upstream)"/"recommended".
- Consider removing automatic redirection entirely and instead only using the metadata to *display* provenance information for the user to manually re-run `gh skill install <claimed-upstream> ...` themselves.

### Proof of Concept
1. Attacker publishes `attacker/mirror-skills` containing `skills/git-commit/SKILL.md` with frontmatter:
```yaml
---
name: git-commit
description: Writes commits
metadata:
  github-repo: https://github.com/attacker/payload-skills
  github-tree-sha: <attacker-controlled>
  github-path: skills/git-commit
---
```
2. Victim runs:
```
gh skill install attacker/mirror-skills git-commit --upstream
```
3. `checkUpstreamProvenance` reads the frontmatter, sees `opts.Upstream == true`, and returns `upstreamRepo = attacker/payload-skills` [5](#0-4) .
4. `installRun` swaps `opts.repo` to `attacker/payload-skills` and restarts install [6](#0-5) , ultimately writing files sourced entirely from `attacker/payload-skills` to the victim's `.copilot/skills/git-commit/` (or equivalent) directory.

### Citations

**File:** pkg/cmd/skills/install/install.go (L350-369)
```go
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

**File:** pkg/cmd/skills/install/install.go (L1343-1371)
```go
	cs := opts.IO.ColorScheme()
	upstreamLabel := ghrepo.FullName(upstreamRepo)
	repoSource := ghrepo.FullName(opts.repo)

	fmt.Fprintf(opts.IO.ErrOut, "%s This skill was originally published in %s\n", cs.WarningIcon(), upstreamLabel)

	if opts.Upstream {
		fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
		return upstreamRepo, true, nil
	}

	if !opts.IO.CanPrompt() {
		fmt.Fprintf(opts.IO.ErrOut, "  Installing from %s (use --upstream or interactive mode to choose upstream)\n", repoSource)
		return nil, true, nil
	}

	choices := []string{
		fmt.Sprintf("%s (re-publisher, recommended)", repoSource),
		fmt.Sprintf("%s (upstream)", upstreamLabel),
	}
	idx, err := opts.Prompter.Select("Install from:", "", choices)
	if err != nil {
		return nil, true, err
	}

	if idx == 1 {
		fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
		return upstreamRepo, true, nil
	}
```

**File:** internal/skills/installer/installer.go (L251-309)
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

	return nil
}
```
