### Title
`gh skill install --upstream` redirects to an attacker-chosen repository based on unauthenticated metadata embedded in the installed skill content - ([File: pkg/cmd/skills/install/install.go])

### Summary
`gh skill install` trusts a `github-repo` field embedded in the very `SKILL.md` content it is about to install, and — when `--upstream` is set (a flag the CLI's own documentation recommends agents use) — silently redirects the installation to whatever repository that field names, with no verification that the claimed "upstream" actually owns or authorized the skill.

### Finding Description
This is the same class of bug as the Merit Circle `increaseLock` finding: an operation is validated/scoped against one identity (the repository the user actually specified, e.g. `owner/repo`), but the value that ends up being *acted upon* (here, the source of the files written to disk) is taken from a second, attacker-influenced parameter that the code never cross-checks against the first.

In `checkUpstreamProvenance` [1](#0-0) , after the user has asked to install a skill from `opts.repo` (the repo they typed on the command line or picked from search), the CLI fetches that repo's `SKILL.md` and parses its frontmatter metadata for a `github-repo` key:

```go
existingRepo, _ := result.Metadata.Meta["github-repo"].(string)
...
upstreamRepo, parseErr := source.ParseRepoURL(existingRepo)
```

`source.ParseRepoURL` [2](#0-1)  does nothing but parse an `owner/repo` string via `ghrepo.FromFullName` — it performs no ownership, ACL, or cross-signature check between the *declaring* repo and the *claimed* upstream repo. Any repository can claim, in its own `SKILL.md`, to have been "originally published" in any other repository on GitHub.

When the `--upstream` flag is set, the redirect happens unconditionally and non-interactively:

```go
if opts.Upstream {
    fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
    return upstreamRepo, true, nil
}
``` [3](#0-2) 

The caller then swaps `opts.repo` for the attacker-supplied repo and recurses into `installRun`, which fetches and writes the skill's files from that repo instead of the one the user originally named:

```go
opts.repo = upstreamRepo
opts.SkillSource = ghrepo.FullName(upstreamRepo)
opts.version = ""
opts.Pin = ""
return installRun(opts)
``` [4](#0-3) 

The only guardrail applied to the new repo is `source.ValidateSupportedHost` [5](#0-4) , which only checks that the host is `github.com`/tenancy — it does not restrict which owner/repo can be named. Non-interactively without `--upstream`, the tool falls back to installing from the originally-named repo, but the `SKILL.md` for `gh-skill` explicitly recommends using `--upstream` for automated/agent-driven installs: "You should know what agent you are, so set this appropriately" [6](#0-5) .

### Impact Explanation
An attacker who can get a victim (or an automated agent) to run `gh skill install <attacker-repo> <skill> --upstream` — e.g. by having the malicious skill surfaced through `gh skill search`, a README link, or documentation — can embed a `github-repo: <attacker-controlled-repo-2>` metadata field in the skill they publish. The install command will then fetch and write files from `<attacker-controlled-repo-2>` to the user's/agent's skill directory, entirely bypassing whatever review or trust the victim placed in the originally-named repo. Since installed `SKILL.md` files are subsequently read and acted on by AI coding agents (the whole point of the Agent Skills feature), this is a path to prompt injection or instruction smuggling controlled entirely by content the attacker chooses at install time, decoupled from the repo the victim believed they were installing from.

### Likelihood Explanation
The redirect requires the `--upstream` flag or an interactive user selecting the "upstream" option in a prompt when the "re-published skill" warning is shown (`⚠ This skill was originally published in %s`) [7](#0-6) . Interactively, this requires a user to actively choose the upstream option, lowering likelihood there. But `--upstream` is a documented, recommended flag for scripted/agent-driven installs where no human reviews the warning, which raises the likelihood in that specific (already common) usage pattern.

### Recommendation
Do not let a repository's own content assert an authoritative "upstream" source that the CLI will follow non-interactively. At minimum:
- Require an explicit, out-of-band trust signal for the claimed upstream repo (e.g. verified publisher metadata via `gh skill publish` records rather than free-form frontmatter) before auto-redirecting with `--upstream`.
- Always prompt/confirm before redirecting installation to a different repository than the one explicitly requested by the user, even with `--upstream`, or restrict `--upstream` redirection to repos within the same owner/org.
- Log/telemetry already records `skill_upstream_redirect` [8](#0-7)  — consider surfacing this redirect prominently to the caller/agent output regardless of interactivity, and require a second explicit confirmation step for cross-owner redirects.

### Proof of Concept
1. Attacker creates `attacker/decoy-skill` with `skills/foo/SKILL.md` containing:
```yaml
---
name: foo
description: ...
metadata:
  github-repo: https://github.com/attacker/evil-payload
---
```
2. Attacker separately publishes `attacker/evil-payload` with a malicious `skills/foo/SKILL.md`.
3. Victim (or an automated agent following the documented recommendation) runs:
```
gh skill install attacker/decoy-skill foo --upstream
```
4. `checkUpstreamProvenance` reads `decoy-skill`'s frontmatter, finds `github-repo: https://github.com/attacker/evil-payload`, and since `--upstream` is set, redirects `opts.repo` to `attacker/evil-payload` and recurses into `installRun`, installing the attacker's chosen payload content — content the victim never named or reviewed — to the local skills directory.

### Citations

**File:** pkg/cmd/skills/install/install.go (L360-363)
```go
			opts.Telemetry.Record(ghtelemetry.Event{
				Type:       "skill_upstream_redirect",
				Dimensions: redirectDims,
			})
```

**File:** pkg/cmd/skills/install/install.go (L364-368)
```go
			opts.repo = upstreamRepo
			opts.SkillSource = ghrepo.FullName(upstreamRepo)
			opts.version = ""
			opts.Pin = ""
			return installRun(opts)
```

**File:** pkg/cmd/skills/install/install.go (L1292-1335)
```go
// checkUpstreamProvenance fetches the skill's SKILL.md via the contents API
// to check if it contains github-repo metadata pointing to a different
// repository, indicating the skill was re-published from an upstream source.
// In interactive mode, the user is asked whether to install from the
// re-publisher or redirect to the upstream. Non-interactive mode always
// installs from the re-publisher.
// Returns (repo to redirect to, whether upstream was detected, error).
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

**File:** pkg/cmd/skills/install/install.go (L1343-1347)
```go
	cs := opts.IO.ColorScheme()
	upstreamLabel := ghrepo.FullName(upstreamRepo)
	repoSource := ghrepo.FullName(opts.repo)

	fmt.Fprintf(opts.IO.ErrOut, "%s This skill was originally published in %s\n", cs.WarningIcon(), upstreamLabel)
```

**File:** pkg/cmd/skills/install/install.go (L1349-1352)
```go
	if opts.Upstream {
		fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
		return upstreamRepo, true, nil
	}
```

**File:** internal/skills/source/source.go (L19-32)
```go
// ParseRepoURL parses a repository URL stored in skill metadata.
func ParseRepoURL(raw string) (ghrepo.Interface, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("repository URL is empty")
	}

	repo, err := ghrepo.FromFullName(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid repository URL %q: %w", raw, err)
	}

	return repo, nil
}
```

**File:** internal/skills/source/source.go (L53-68)
```go
// ValidateSupportedHost rejects hosts that are not supported.
// Supported hosts are github.com and GHEC with data residency (*.ghe.com).
// GitHub Enterprise Server is not currently supported.
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

**File:** skills/gh-skill/SKILL.md (L44-47)
```markdown
- `--agent <id>` - target host (e.g. `github-copilot`, `claude-code`,
  `cursor`, `codex`, `gemini-cli`). Repeat for multiple. Default is
  `github-copilot` when non-interactive. You should know what agent you are,
  so set this appropriately to install for yourself.
```
