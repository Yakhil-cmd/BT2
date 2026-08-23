### Title
Case-insensitive skill name collision bypasses `FindNameCollisions` and overwrites an existing skill's files - (File: internal/skills/installer/installer.go)

### Summary
`installLocalSkill` in `internal/skills/installer/installer.go` writes skill files to `filepath.Join(baseDir, skill.Name)` using the raw, attacker-supplied `skill.Name` with no case normalization. The pre-install collision guard, `discovery.FindNameCollisions`, keys skills by the exact `s.Name` string in a Go map, so `My-Skill` and `my-skill` are treated as distinct even though they resolve to the same directory on case-insensitive filesystems (default macOS APFS, Windows NTFS).

### Finding Description
`validateName` in `internal/skills/discovery/discovery.go` explicitly allows mixed-case names (`safeNamePattern = ^[a-zA-Z0-9][a-zA-Z0-9._\- ]*$`, and the test `TestValidateName` confirms `"uppercase allowed": Octocat -> true`) [1](#0-0) [2](#0-1) . Non-ASCII/unicode characters are rejected by this pattern, so the collision only manifests through **case** differences, not Unicode confusables.

The only collision guard, `FindNameCollisions`, groups skills in a plain Go `map[string][]Skill` keyed by the literal `s.Name`, with no case-folding or path normalization [3](#0-2) . This is invoked from `collisionError` in the install command before calling `installer.InstallLocal`/`InstallLocal`, but it only compares skills *within the same install batch/selection* — it never re-checks against skills already present on disk from a prior install [4](#0-3) .

`installLocalSkill` then computes the destination directory directly from `skill.Name`: `skillDir := filepath.Join(baseDir, skill.Name)` [5](#0-4) . On a case-insensitive filesystem, `My-Skill` and `my-skill` resolve to the identical on-disk directory. Because the collision detector does not normalize case, a maliciously crafted skill named e.g. `My-Skill` bundled alongside (or published later than) a legitimately-installed `my-skill` will not be flagged as conflicting, and its files (including `SKILL.md`) will be written into/over the existing skill's directory.

### Impact Explanation
An attacker who publishes a skill with a name that differs only in case from a trusted, already-installed skill can silently overwrite files (including `SKILL.md`, which many agent hosts execute or use as instructions) in the victim's skills directory once the victim installs the attacker's skill. Since `SKILL.md` content can direct agent behavior, this can lead to instruction/content injection that downstream tooling treats as trusted, which is a file-overwrite/content-injection primitive on the victim's machine — potentially escalating to code execution depending on how the consuming agent (e.g., Copilot/agent host) interprets skill content. This is scoped to file overwrite outside the intended, distinctly-named path.

### Likelihood Explanation
Requires: (1) the victim to run on a case-insensitive filesystem (default on macOS and Windows), (2) the victim to already have (or simultaneously select) a skill whose name differs only by case from the attacker's published skill, and (3) the victim to run `gh skills install` against the attacker's local/cloned content via `installLocalSkill`. This is a real but conditional path — it depends on filesystem case-insensitivity and a specific pre-existing/co-selected skill name, so it is not trivially exploitable against an arbitrary victim without some name-guessing or targeting of a well-known skill name.

### Recommendation
Normalize skill names before comparison and before deriving install paths: fold to a canonical case (e.g., lowercase) both in `FindNameCollisions` and in `installLocalSkill`/`installSkill`'s directory computation, and also check collisions against skills already present in the target directory (not just within the current selection batch), rejecting installs when a case-normalized name collides with an existing directory entry unless `--force` is explicitly passed with a clear warning identifying the specific existing skill being overwritten.

### Proof of Concept
```go
// internal/skills/discovery/collisions_test.go (additional case)
func TestFindNameCollisions_CaseInsensitive(t *testing.T) {
    skills := []Skill{
        {Name: "my-skill", Path: "skills/my-skill"},
        {Name: "My-Skill", Path: "skills/My-Skill"},
    }
    got := FindNameCollisions(skills)
    // Currently fails: got is nil because map keys "my-skill" != "My-Skill".
    assert.NotEmpty(t, got, "expected case-insensitive collision to be detected")
}
```
```go
// internal/skills/installer/installer_test.go (filesystem-level PoC, run on case-insensitive FS)
func TestInstallLocalSkill_CaseCollisionOverwrite(t *testing.T) {
    sourceRoot := t.TempDir()
    target := t.TempDir()

    writeSkill(t, sourceRoot, "my-skill", "---\nname: my-skill\n---\ntrusted content")
    require.NoError(t, installLocalSkill(sourceRoot, discovery.Skill{Name: "my-skill", Path: "my-skill"}, target))

    writeSkill(t, sourceRoot, "My-Skill", "---\nname: My-Skill\n---\nATTACKER PAYLOAD")
    require.NoError(t, installLocalSkill(sourceRoot, discovery.Skill{Name: "My-Skill", Path: "My-Skill"}, target))

    data, _ := os.ReadFile(filepath.Join(target, "my-skill", "SKILL.md"))
    // On a case-insensitive filesystem this will contain "ATTACKER PAYLOAD",
    // proving the second install silently overwrote the first.
    assert.NotContains(t, string(data), "ATTACKER PAYLOAD")
}
```

### Citations

**File:** internal/skills/discovery/discovery.go (L1089-1097)
```go
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

**File:** internal/skills/discovery/discovery_test.go (L335-357)
```go
func TestValidateName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty", input: "", want: false},
		{name: "too long", input: strings.Repeat("a", 65), want: false},
		{name: "max length is valid", input: strings.Repeat("a", 64), want: true},
		{name: "contains slash", input: "foo/bar", want: false},
		{name: "contains dotdot", input: "foo..bar", want: false},
		{name: "starts with dot", input: ".hidden", want: false},
		{name: "simple name", input: "code-review", want: true},
		{name: "with dots and underscores", input: "octocat_helper.v2", want: true},
		{name: "uppercase allowed", input: "Octocat", want: true},
		{name: "single char", input: "a", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, validateName(tt.input))
		})
	}
}
```

**File:** internal/skills/discovery/collisions.go (L21-37)
```go
func FindNameCollisions(skills []Skill) []NameCollision {
	byName := make(map[string][]Skill)
	for _, s := range skills {
		byName[s.Name] = append(byName[s.Name], s)
	}

	var collisions []NameCollision
	for name, group := range byName {
		if len(group) <= 1 {
			continue
		}
		names := make([]string, len(group))
		for i, s := range group {
			names[i] = s.DisplayName()
		}
		collisions = append(collisions, NameCollision{Name: name, DisplayNames: names})
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
