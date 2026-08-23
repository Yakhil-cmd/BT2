### Title
Missed skill-name collision detection allows Windows trailing-dot/space directory overwrite - (File: internal/skills/discovery/collisions.go)

### Summary
`FindNameCollisions` groups skills by an exact string match on `Skill.Name`, but `safeNamePattern` permits names ending in a literal dot or space (e.g. `tools.` or `tools `). On Windows, trailing dots and spaces are silently stripped from directory names by the Win32 API, so two skills with names that differ only by a trailing dot/space are installed to the identical directory without any collision being reported, causing one skill's files to silently overwrite the other's.

### Finding Description
`safeNamePattern` is defined as `^[a-zA-Z0-9][a-zA-Z0-9._\- ]*$` [1](#0-0) , which explicitly allows dots and spaces anywhere after the first character, including as the last character, and `matchSkillConventions` derives `skillName` directly from `path.Base(dir)` and validates it with this pattern before constructing the `Skill` struct [2](#0-1) . An attacker publishing a repo can therefore create two skill directories, `skills/tools/SKILL.md` and `skills/tools./SKILL.md` (or `tools `), both of which pass validation and produce `Skill{Name:"tools"}` and `Skill{Name:"tools."}`.

`FindNameCollisions` keys its grouping map directly on `s.Name` with no normalization [3](#0-2) , so `"tools"` and `"tools."` are treated as distinct groups and no collision is reported to the user before install proceeds.

At install time, `installSkill` builds the target directory with `filepath.Join(baseDir, skill.Name)` using the raw, unnormalized `Name` [4](#0-3) , and `installLocalSkill` does the same for local installs [5](#0-4) . On Windows, the underlying Win32 `CreateDirectory`/`CreateFile` APIs (used by Go's `os.MkdirAll`/`os.WriteFile` when not using the `\\?\` long-path prefix) silently strip trailing dots and spaces from path components, so `tools.` and `tools ` resolve to the same on-disk directory as `tools`. Because both skills are processed with `maxConcurrency` workers writing into the same physical directory [6](#0-5) , files from one skill overwrite files from the other with no warning, no error, and no user-visible indication that a name collision occurred.

`safepaths.ParseAbsolute`/`Join` used in the file-writing loop only protects against path traversal (`..` escapes), not against OS-level filename canonicalization differences, so it does not catch this case [7](#0-6) .

### Impact Explanation
This is a file overwrite / silent skill substitution issue confined to a directory the victim intended to write to (`PATH_CONFINEMENT`-adjacent but not an escape outside the intended tree). A malicious repo owner can craft two skills such that a trusted-looking skill (e.g. `tools`) is silently replaced by an attacker-controlled skill (`tools.`) at install time on Windows, changing which `SKILL.md`/scripts end up served to the agent under the expected name, with no collision warning shown to the user via `FormatCollisions`. This does not achieve arbitrary code execution or a path traversal outside the target skills directory, but it does defeat the collision-detection safety mechanism the code explicitly claims to provide, resulting in unintended file overwrite/content substitution within the install directory.

### Likelihood Explanation
Preconditions: the victim must be on Windows and run `gh skill install owner/repo --all` (or otherwise install multiple skills from an attacker-controlled repo) where the repo defines both `tools` and `tools.`/`tools ` skill directories. This requires no privileges beyond publishing a public repository, and is fully attacker-controlled and repeatable — the attacker fully controls the skill names via directory names in their own repo.

### Recommendation
Normalize skill names before both collision detection and directory creation: reject or canonicalize names with trailing dots/spaces (or any trailing whitespace/dot) in `safeNamePattern`/`validateName`, and/or have `FindNameCollisions` compare a normalized form (e.g. `strings.TrimRight(name, ". ")`, case-folded per target OS) rather than the raw `Name` string. Additionally, consider validating that the final `skillDir` computed from `skill.Name` does not collide (via `os.Stat`/case+trim-insensitive comparison) with another skill's target directory before writing.

### Proof of Concept
```go
func TestFindNameCollisions_MissesTrailingDotVariant(t *testing.T) {
    skills := []discovery.Skill{
        {Name: "tools"},
        {Name: "tools."}, // passes safeNamePattern, distinct map key
    }
    collisions := discovery.FindNameCollisions(skills)
    if len(collisions) != 0 {
        t.Fatalf("expected no collisions to be detected (demonstrating the bug), got %v", collisions)
    }
    // On a real Windows filesystem, filepath.Join(base, "tools") and
    // filepath.Join(base, "tools.") resolve to the identical directory
    // because Win32 CreateDirectory/CreateFile strip trailing dots/spaces
    // from path components not using the \\?\ prefix, so installing both
    // skills sequentially/concurrently causes one to overwrite the other
    // with no warning surfaced via FormatCollisions.
}
```
This assertion demonstrates that `FindNameCollisions` fails to flag a name pair that maps to the same directory on Windows; the on-disk overwrite itself is a platform (Win32 filesystem) behavior and would need to be confirmed on an actual Windows host or Windows-path-emulation harness, since the sandbox used for this analysis does not have a Windows filesystem to directly execute the overwrite.

### Citations

**File:** internal/skills/discovery/discovery.go (L39-42)
```go
// safeNamePattern matches names that are safe for filesystem use during discovery.
// Allows letters (any case), numbers, hyphens, underscores, dots, and spaces.
// Must start with a letter or number. This matches copilot-agent-runtime's SKILL_NAME_REGEX.
var safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\- ]*$`)
```

**File:** internal/skills/discovery/discovery.go (L438-452)
```go
func matchSkillConventions(entry treeEntry) *skillMatch {
	if path.Base(entry.Path) != "SKILL.md" {
		return nil
	}

	dir := path.Dir(entry.Path)
	parentDir := path.Dir(dir)
	skillName := path.Base(dir)

	if !validateName(skillName) {
		return nil
	}

	if parentDir == "skills" {
		return &skillMatch{entry: entry, name: skillName, skillDir: dir, convention: "skills"}
```

**File:** internal/skills/discovery/collisions.go (L21-26)
```go
func FindNameCollisions(skills []Skill) []NameCollision {
	byName := make(map[string][]Skill)
	for _, s := range skills {
		byName[s.Name] = append(byName[s.Name], s)
	}

```

**File:** internal/skills/installer/installer.go (L100-118)
```go
	workers := min(maxConcurrency, total)
	for range workers {
		wg.Go(func() {
			for j := range jobs {
				err := installSkill(opts, j.skill, targetDir)
				results[j.idx] = skillResult{name: j.skill.InstallName(), err: err}

				if opts.OnProgress != nil {
					opts.OnProgress(int(done.Add(1)), total)
				}
			}
		})
	}

	for i, s := range opts.Skills {
		jobs <- job{idx: i, skill: s}
	}
	close(jobs)
	wg.Wait()
```

**File:** internal/skills/installer/installer.go (L180-187)
```go
func installLocalSkill(sourceRoot string, skill discovery.Skill, baseDir string) error {
	// Use skill.Name (not InstallName) so skills are always installed flat.
	// Most agent clients only discover immediate subdirectories of their
	// skills folder and do not find skills nested under namespace directories.
	skillDir := filepath.Join(baseDir, skill.Name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return fmt.Errorf("could not create directory %s: %w", skillDir, err)
	}
```

**File:** internal/skills/installer/installer.go (L251-256)
```go
func installSkill(opts *Options, skill discovery.Skill, baseDir string) error {
	// Use skill.Name (not InstallName) for a flat directory layout.
	skillDir := filepath.Join(baseDir, skill.Name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return fmt.Errorf("could not create directory %s: %w", skillDir, err)
	}
```

**File:** internal/skills/installer/installer.go (L263-288)
```go
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
```
