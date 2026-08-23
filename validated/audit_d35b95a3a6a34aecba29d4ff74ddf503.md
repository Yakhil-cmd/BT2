### Title
Unverified `github-repo` upstream redirect in `gh skill install --upstream` allows attacker-controlled content substitution - ([File: pkg/cmd/skills/install/install.go])

### Summary
`gh skill install` supports a "republished skill" detection feature: when installing a skill, it inspects the `SKILL.md` frontmatter of the *source repository the user explicitly requested* for a `github-repo` metadata field, and if present, treats it as the "true" upstream origin. When `--upstream` is passed (or the user picks the upstream choice interactively), the CLI blindly redirects the entire install operation to whatever repository is named in that field, with no verification that the named repository is actually the legitimate origin of the skill.

### Finding Description
`checkUpstreamProvenance` fetches the `SKILL.md` of the repo the user asked to install from, parses its frontmatter, and pulls out the self-declared `github-repo` value: [1](#0-0) 

If that metadata is present and differs from the requested repo, and the caller passed `--upstream`, the code redirects the install to the parsed repository without any additional verification and re-enters `installRun` with the new target: [2](#0-1) 

The value that drives this redirect is fully attacker-controlled: `github-repo` is just a frontmatter field inside the content of the skill being installed, and any GitHub user can publish a repository containing a `SKILL.md` with a fabricated `github-repo: <attacker/repo>` value: [3](#0-2) 

This is architecturally analogous to the WOOFi Solana `create_oracle`/`create_pool` bug: in that case, anyone could create an unprivileged "oracle" account and later have it trusted as an authoritative price source purely because a downstream instruction (`create_pool`) matched on the oracle's self-declared `authority` field rather than validating it against the real protocol admin. Here, anyone can publish a repository whose self-declared `github-repo` metadata is trusted as the authoritative "upstream" source, and the install flow redirects to it without validating that the claimed upstream actually owns or matches the original skill content.

### Impact Explanation
A user who runs `gh skill install <attacker-controlled-or-compromised-repo> <skill> --upstream` (a documented, supported usage pattern — see the `--upstream` flag description and example in the same file) can be silently redirected to install skill content from an entirely different, attacker-chosen repository: [4](#0-3) 

The redirected install then fetches and writes the attacker-chosen repo's files into the user's skill directories (e.g. `.claude/skills`, `.copilot/skills`) via the normal install pipeline, meaning arbitrary attacker-authored `SKILL.md`/instruction content ends up installed and later consumed/executed by AI coding agents. Since these skills are designed to be read and acted upon by agents (shell commands, code changes, etc.), this is a supply-chain vector: an attacker republishing or compromising a popular skill can point the "upstream" redirect at their own malicious repository, and any user or automation relying on `--upstream` to "get the real source" instead gets attacker content.

### Likelihood Explanation
Exploitation only requires the attacker to publish a public GitHub repository containing a skill with fabricated `github-repo` frontmatter — no special privileges, no compromise of GitHub infrastructure, and no interaction beyond a victim running the documented `--upstream` flag or accepting the interactive upstream prompt (whose text explicitly recommends the option is available and shows the attacker-controlled name as the "upstream"): [5](#0-4) 

### Recommendation
Do not trust self-declared `github-repo` metadata as an authorization/authenticity signal for redirecting installs. At minimum:
- Require the claimed upstream repository to also declare (or cryptographically attest, e.g. via commit signature/attestation) a matching relationship back to the re-publisher, rather than accepting a one-directional, attacker-controlled pointer.
- Before installing from the "upstream" target, diff/compare content hashes to confirm the upstream skill is substantively the same as the one the user originally selected, and surface any material differences prominently instead of silently proceeding.
- Treat `--upstream` redirection as advisory only, always showing the resolved final repo/owner and requiring explicit confirmation even in non-interactive/CI contexts, rather than defaulting to trust it as "recommended".

### Proof of Concept
1. Attacker creates `evil/skills-repo` containing `skills/git-commit/SKILL.md` with legitimate-looking content but frontmatter:
   ```yaml
   metadata:
     github-repo: https://github.com/evil/payload-repo
   ```
2. Attacker publishes/promotes `evil/skills-repo` (e.g., as a "mirror" or "republished" copy of a popular skill).
3. Victim runs:
   ```
   gh skill install evil/skills-repo git-commit --upstream
   ```
4. `checkUpstreamProvenance` reads the fabricated `github-repo` field and, because `--upstream` is set, redirects the entire install to `evil/payload-repo` with no validation: [6](#0-5) 
5. The CLI installs `evil/payload-repo`'s skill content — fully attacker-controlled instructions — into the victim's agent skill directory, which is subsequently read and acted on by the AI agent.

### Citations

**File:** pkg/cmd/skills/install/install.go (L245-249)
```go
	cmd.Flags().BoolVar(&opts.All, "all", false, "Install all skills without prompting for skill selection")
	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Overwrite existing skills without prompting")
	cmd.Flags().BoolVar(&opts.FromLocal, "from-local", false, "Treat the argument as a local directory path instead of a repository")
	cmd.Flags().BoolVar(&opts.AllowHiddenDirs, "allow-hidden-dirs", false, "Include skills in hidden directories (e.g. .claude/skills/, .agents/skills/)")
	cmd.Flags().BoolVar(&opts.Upstream, "upstream", false, "Install from the upstream source when a re-published skill is detected")
```

**File:** pkg/cmd/skills/install/install.go (L1292-1341)
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

	upstreamRepo, parseErr := source.ParseRepoURL(existingRepo)
	if parseErr != nil {
		//nolint:nilerr // invalid repo URL means we can't redirect; install normally
		return nil, false, nil
	}
```

**File:** pkg/cmd/skills/install/install.go (L1343-1362)
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
