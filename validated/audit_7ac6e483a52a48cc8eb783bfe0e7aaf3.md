### Title
Skill name collision detection is not filesystem-normalization aware, enabling concurrent overwrite of a reviewed skill's files during multi-skill `Install` - ([File: internal/skills/installer/installer.go], [File: pkg/cmd/skills/install/install.go])

### Finding Description
`Install` (`internal/skills/installer/installer.go:56-142`) builds a worker pool of `workers := min(maxConcurrency, total)` goroutines that each call `installSkill(opts, j.skill, targetDir)` concurrently for every skill in `opts.Skills` [1](#0-0) . `installSkill` derives `skillDir := filepath.Join(baseDir, skill.Name)` and independently `os.MkdirAll`s that directory and `os.WriteFile`s each fetched blob into it [2](#0-1) , with no locking or per-directory synchronization across goroutines.

The only defense against name collisions is `discovery.FindNameCollisions`, which groups skills by exact byte-equality of `skill.Name` in a Go map and reports a collision only when two entries produce the *identical* string key [3](#0-2) . This is invoked as `collisionError` prior to installation to reject conflicting names [4](#0-3) .

`validateName`, which gates what `skill.Name` values are accepted during discovery, permits any mixed-case alphanumeric name matching `^[a-zA-Z0-9][a-zA-Z0-9._\- ]*$`, including names differing only in letter case or trailing dots/spaces [5](#0-4) . Neither `validateName` nor `FindNameCollisions` normalizes names for filesystem case-insensitivity (default on macOS APFS/HFS+ and Windows NTFS) or Windows' trailing-dot/space stripping behavior. Consequently, an attacker-controlled repository can publish two skills, e.g. `Foo/SKILL.md` and `foo/SKILL.md`, which:
1. Pass `validateName` individually (both are valid names).
2. Are treated as distinct, non-colliding entries by `FindNameCollisions`/`collisionError` (exact string comparison: `"Foo" != "foo"`).
3. Resolve to the identical on-disk `skillDir` when `filepath.Join(baseDir, skill.Name)` is evaluated on a case-insensitive filesystem.

When a victim selects both skills in one `gh skill install --all` (or equivalent multi-select) invocation, `Install` schedules `installSkill(Foo)` and `installSkill(foo)` in separate goroutines from the worker pool, each independently `MkdirAll`-ing and `WriteFile`-ing into the same resolved directory without coordination. The result is a race where files from one skill (including SKILL.md, which carries attacker-controlled/injected metadata) can interleave with or overwrite files from the other skill after installation completes. `printReviewHint` (`pkg/cmd/skills/install/install.go:1198-1221`) then only ever names one `InstallName()`/`skillNames` entry per logical skill the victim thinks they reviewed, so the on-disk content silently diverges from what the victim reviewed via `gh skill preview` for the colliding entry — a 1:1 verification-to-artifact correspondence bypass.

### Impact Explanation
This is a file-write/content-confusion vulnerability under the "content-confusion allowing a malicious skill's files to masquerade as a different, seemingly-reviewed skill's files" impact class. The scoped impact is limited to intra-installation confusion between skills the victim explicitly chose to install from the same attacker repo/ref in the same batch; it does not escape `targetDir` (path traversal is separately guarded by `safepaths.ParseAbsolute`/`Join` at installer.go:263-288) and does not achieve arbitrary code execution by itself, but it does let an attacker's payload silently overwrite a reviewed skill's `SKILL.md`/scripts post-hoc, undermining the "review before use" trust model that `printPreInstallDisclaimer`/`printReviewHint` rely on.

### Likelihood Explanation
Requires: (1) victim's OS/filesystem is case-insensitive (default macOS, default Windows) or otherwise normalizes distinct byte-sequences to the same path; (2) attacker publishes two names differing only in case (or Windows-trimmed trailing dot/space) within one repo; (3) victim selects both in a single multi-skill install (`--all` or manual multi-select) so they land in the same worker-pool batch. All of these are attacker/victim-controllable without special privileges — the attacker just needs to publish a repo with the colliding directory names, which passes existing per-name validation and the exact-string collision check.

### Recommendation
Normalize skill names before collision detection and before deriving `skillDir`: compare `strings.ToLower(skill.Name)` (and account for Windows trailing dot/space stripping, e.g. via `strings.TrimRight(name, ". ")`) in `discovery.FindNameCollisions`, or better, resolve each `skillDir` via `filepath.EvalSymlinks`/case-folding comparison and reject the install if two resolved directories coincide, regardless of source string equality. Additionally, `Install`'s worker pool should track already-claimed target directories (e.g. a `map[string]struct{}` guarded by mutex or a pre-flight duplicate check on normalized `skillDir` values) and fail fast rather than relying solely on `installSkill.Name` equality.

### Proof of Concept
```go
func TestFindNameCollisions_CaseInsensitiveMiss(t *testing.T) {
    skills := []discovery.Skill{
        {Name: "Foo", Path: "skills/Foo"},
        {Name: "foo", Path: "skills/foo"},
    }
    // Exact-match check reports no collision even though "Foo" and "foo"
    // resolve to the same directory on case-insensitive filesystems.
    collisions := discovery.FindNameCollisions(skills)
    assert.Empty(t, collisions) // demonstrates the gap
}

func TestInstall_CaseCollisionRace(t *testing.T) {
    // Simulate a case-insensitive FS test double or run on macOS/Windows CI.
    opts := &installer.Options{
        Skills: []discovery.Skill{
            {Name: "Foo", Path: "skills/Foo", TreeSHA: "shaA"},
            {Name: "foo", Path: "skills/foo", TreeSHA: "shaB"},
        },
        Dir: t.TempDir(),
        // ... Client stubbed via httpmock to serve distinct SKILL.md content per TreeSHA
    }
    result, err := installer.Install(opts)
    // Expect either a hard error preventing install, or that exactly one
    // skill's content deterministically occupies the directory with no
    // interleaved bytes from the other skill's blobs.
    require.NoError(t, err)
    content, _ := os.ReadFile(filepath.Join(result.Dir, "Foo", "SKILL.md"))
    assert.NotContains(t, string(content), "interleaved-or-corrupted-marker")
}
```
Run repeatedly (`go test -race -count=50`) on a case-insensitive filesystem to observe non-deterministic content/interleaving between the two `installSkill` goroutines writing to the same resolved path.

### Citations

**File:** internal/skills/installer/installer.go (L100-112)
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

**File:** internal/skills/discovery/collisions.go (L21-26)
```go
func FindNameCollisions(skills []Skill) []NameCollision {
	byName := make(map[string][]Skill)
	for _, s := range skills {
		byName[s.Name] = append(byName[s.Name], s)
	}

```

**File:** pkg/cmd/skills/install/install.go (L903-911)
```go
// collisionError checks for name collisions among the selected skills.
func collisionError(ss []discovery.Skill) error {
	collisions := discovery.FindNameCollisions(ss)
	if len(collisions) == 0 {
		return nil
	}
	return fmt.Errorf("cannot install skills with conflicting names; they would overwrite each other:\n  %s",
		discovery.FormatCollisions(collisions))
}
```

**File:** internal/skills/discovery/discovery.go (L1088-1097)
```go
// validateName checks if a skill name is safe for use (filesystem-safe).
func validateName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		return false
	}
	return safeNamePattern.MatchString(name)
}
```
