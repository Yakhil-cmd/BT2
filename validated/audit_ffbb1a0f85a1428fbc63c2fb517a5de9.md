### Title
Case-sensitive `FindNameCollisions` allows silent overwrite of approved skills on case-insensitive filesystems - ([File: internal/skills/discovery/collisions.go])

### Summary
`FindNameCollisions` groups skills by an exact-match `s.Name` string comparison, but `installer.installSkill` writes files to `filepath.Join(baseDir, skill.Name)`. On a case-insensitive filesystem (default macOS APFS, Windows NTFS), two skills whose names differ only by case are treated as distinct by the collision detector but resolve to the identical on-disk directory during install, allowing one skill's files to silently clobber another's without ever triggering `collisionError`.

### Finding Description
`FindNameCollisions` builds a map keyed by the raw `s.Name` value and only flags collisions when two skills share the exact same string [1](#0-0) . The directory-name pattern used during discovery, `safeNamePattern`, explicitly permits letters of any case (`^[a-zA-Z0-9][a-zA-Z0-9._\- ]*$`), so `Foo` and `foo` are both valid, distinct `Skill.Name` values that survive discovery unnormalized [2](#0-1) . `collisionError` in the install command calls `discovery.FindNameCollisions(ss)` and only errors if it returns non-empty results [3](#0-2) ; with `Foo` vs `foo` this check passes silently. `installSkill` then computes the destination as `filepath.Join(baseDir, skill.Name)` and writes files under it via `os.MkdirAll`/`os.WriteFile` [4](#0-3) . On a case-insensitive filesystem, `baseDir/Foo` and `baseDir/foo` are the same physical directory, so installing both skills in one `--all` invocation causes the second skill's `SKILL.md` and scripts to overwrite the first's files at the OS level, even though the tool's own collision gate reported no conflict.

### Impact Explanation
This is a file-write/overwrite outside the intended safety gate: content a user believed was distinct and individually reviewed is silently replaced by attacker-supplied content sharing a case-differing name, without the "cannot install skills with conflicting names" warning ever surfacing. This corresponds to a file overwrite / confirmation-bypass class of impact — an attacker who publishes a repo with `skills/Foo/` and `skills/foo/` can guarantee their chosen skill "wins" the collision, undermining the review workflow `gh skill install --all` relies on.

### Likelihood Explanation
Requires the victim to run `gh skill install --all owner/repo` against an attacker-controlled repository on a case-insensitive filesystem (macOS default APFS or Windows NTFS are both common victim environments). No special privileges, tokens, or MITM are needed — an attacker just needs to publish a public repo with two same-name-different-case skill directories. This is straightforward and repeatable.

### Recommendation
Normalize skill names for collision detection and directory placement (e.g., lowercase comparison, or use a canonicalized key such as `strings.ToLower(s.Name)`) in `FindNameCollisions`, and/or reject skill names that only differ by case within the same discovery run. Alternatively, detect the underlying filesystem's case sensitivity and fold names accordingly before writing.

### Proof of Concept
1. Unit test `collisions_test.go`: call `FindNameCollisions([]Skill{{Name:"Foo"},{Name:"foo"}})` and assert the result is empty, demonstrating no collision is reported.
2. Integration test in `installer_test.go` using a temp directory on a case-insensitive filesystem (or a stub FS asserting case folding): call `installSkill` for skill `Foo` writing `SKILL.md` with content A, then call `installSkill` for skill `foo` writing content B into the same `baseDir`; assert that the on-disk file now contains content B, showing content A was silently overwritten with no error surfaced by `collisionError`.

### Citations

**File:** internal/skills/discovery/collisions.go (L21-26)
```go
func FindNameCollisions(skills []Skill) []NameCollision {
	byName := make(map[string][]Skill)
	for _, s := range skills {
		byName[s.Name] = append(byName[s.Name], s)
	}

```

**File:** internal/skills/discovery/discovery.go (L39-53)
```go
// safeNamePattern matches names that are safe for filesystem use during discovery.
// Allows letters (any case), numbers, hyphens, underscores, dots, and spaces.
// Must start with a letter or number. This matches copilot-agent-runtime's SKILL_NAME_REGEX.
var safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\- ]*$`)

// Skill represents a discovered skill in a repository.
type Skill struct {
	Name        string
	Namespace   string // author/scope prefix for namespaced skills
	Description string
	Path        string // path within the repo, e.g. "skills/git-commit"
	BlobSHA     string // SHA of the SKILL.md blob
	TreeSHA     string // SHA of the skill directory tree
	Convention  string // which directory convention matched
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

**File:** internal/skills/installer/installer.go (L251-256)
```go
func installSkill(opts *Options, skill discovery.Skill, baseDir string) error {
	// Use skill.Name (not InstallName) for a flat directory layout.
	skillDir := filepath.Join(baseDir, skill.Name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return fmt.Errorf("could not create directory %s: %w", skillDir, err)
	}
```
