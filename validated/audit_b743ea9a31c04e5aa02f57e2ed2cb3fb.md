### Title
`MkdirAll` on unvalidated skill name creates directories outside the install root before path checks run - (File: internal/skills/installer/installer.go)

### Summary
`updateSkillInPlace` (`pkg/cmd/skills/update/update.go:418`) delegates directory creation to `installer.Install`, which calls `installSkill`/`installLocalSkill`. Both functions build `skillDir := filepath.Join(baseDir, skill.Name)` and call `os.MkdirAll(skillDir, 0o755)` **before** any `safepaths` validation is performed, so a malicious `skill.Name` containing `../` segments lets an attacker create directories outside the staging/install root.

### Finding Description
In `installSkill`: [1](#0-0) 
`skillDir` is computed by joining the caller-supplied `baseDir` with `skill.Name` and `os.MkdirAll` is invoked immediately. Only afterwards is `safepaths.ParseAbsolute(skillDir)` called, and that call merely parses the already-created (and potentially already-escaped) path for use in subsequent per-file `safeSkillDir.Join(relPath)` checks — it does not undo or detect the fact that `MkdirAll` already ran on an unvalidated, traversal-containing path. The identical pattern exists in `installLocalSkill`: [2](#0-1) 

`skill.Name` originates from `discovery.Skill`, which is populated from the published skill's SKILL.md frontmatter/registry metadata during discovery — data fully controlled by whoever publishes the skill repo. `updateSkillInPlace` passes this untrusted `discovery.Skill` straight into `installer.Install` via `Skills: []discovery.Skill{u.skill}`: [3](#0-2) 

If `skill.Name` is set to a value like `"../../../../tmp/evil"`, `filepath.Join(baseDir, skill.Name)` resolves outside `baseDir` (the update's per-skill staging directory), and `os.MkdirAll` will create that directory tree on disk immediately — before `safepaths.ParseAbsolute`/`Join` ever gets a chance to reject it. The later per-file safepaths check on `relPath` only protects individual file writes within `skillDir`; it does not retroactively validate or roll back the directory creation that already escaped the root.

### Impact Explanation
This allows an attacker who publishes a skill (via a GitHub repo/registry metadata that `gh skills update` fetches) to force directory creation anywhere the running user has filesystem permissions, ahead of the write-path validation that the code otherwise relies on. Combined with subsequent file writes into that structure (or race-condition planting of files that other tools consume, e.g. shell startup files or git hooks directories), this is a Critical arbitrary file write/overwrite-outside-intended-directory primitive matching the GitHub bounty "arbitrary file write" impact class.

### Likelihood Explanation
The attacker only needs to publish a skill whose discovered `Name` (derived from frontmatter/registry metadata) contains path traversal segments; no privileged access is required, and the victim need only run `gh skills update` against an already-installed skill pointing at the attacker's repo/ref. The flaw is deterministic and repeatable — every `installSkill`/`installLocalSkill` call is affected, not just an edge case.

### Recommendation
Validate/resolve `skill.Name` with `safepaths.ParseAbsolute(baseDir).Join(skill.Name)` (or equivalent) and reject traversal *before* calling `os.MkdirAll` for `skillDir`, mirroring the check already applied to `relPath` for individual files. Do not create any directory from an untrusted name until the fully resolved path is confirmed to be inside `baseDir`.

### Proof of Concept
Go unit test sketch for `internal/skills/installer`:
```go
func TestInstallSkill_RejectsTraversalName(t *testing.T) {
    tmp := t.TempDir()
    baseDir := filepath.Join(tmp, "staging")
    _ = os.MkdirAll(baseDir, 0o755)

    outsideMarker := filepath.Join(tmp, "escaped")

    skill := discovery.Skill{
        Name: "../../escaped", // attacker-controlled via frontmatter/registry metadata
        Path: "skills/author/evil",
        // ... TreeSHA etc mocked via httpmock
    }

    opts := &Options{Dir: baseDir, Skills: []discovery.Skill{skill} /* + mocked Client */}
    _, _ = Install(opts)

    if _, err := os.Stat(outsideMarker); err == nil {
        t.Fatalf("directory was created outside install root: %s", outsideMarker)
    }
}
```
Expected (current, buggy) behavior: the directory at `outsideMarker` exists because `os.MkdirAll(filepath.Join(baseDir, skill.Name), ...)` in `installSkill` runs before any `safepaths` check. Expected (fixed) behavior: `Install` returns a path-traversal error and no directory is created outside `baseDir`.

### Citations

**File:** internal/skills/installer/installer.go (L180-199)
```go
func installLocalSkill(sourceRoot string, skill discovery.Skill, baseDir string) error {
	// Use skill.Name (not InstallName) so skills are always installed flat.
	// Most agent clients only discover immediate subdirectories of their
	// skills folder and do not find skills nested under namespace directories.
	skillDir := filepath.Join(baseDir, skill.Name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return fmt.Errorf("could not create directory %s: %w", skillDir, err)
	}

	srcDir := filepath.Join(sourceRoot, filepath.FromSlash(skill.Path))
	absSource, err := filepath.Abs(srcDir)
	if err != nil {
		return fmt.Errorf("could not resolve source path: %w", err)
	}

	safeSkillDir, err := safepaths.ParseAbsolute(skillDir)
	if err != nil {
		return fmt.Errorf("could not resolve target path: %w", err)
	}

```

**File:** internal/skills/installer/installer.go (L251-266)
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
```

**File:** pkg/cmd/skills/update/update.go (L436-450)
```go
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
