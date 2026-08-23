### Title
Flat by-name skill install directory allows cross-repository provenance overwrite - ([File: internal/skills/installer/installer.go], [internal/skills/lockfile/lockfile.go])

### Summary
`gh skill install` writes skills to a directory keyed solely by `skill.Name` (flat layout), with no check for a pre-existing skill installed from a different host/owner/repo. A subsequent install of a same-named skill from an attacker-controlled repository silently overwrites the previously-trusted skill's files and its lockfile provenance record, since `FindNameCollisions` only detects collisions within a single discovery batch (skills found in the same `opts.repo`) and never inspects on-disk state or the `.skill-lock.json` history.

### Finding Description
`installSkill` in `internal/skills/installer/installer.go:251-256` computes the destination purely as `filepath.Join(baseDir, skill.Name)` and unconditionally does `os.MkdirAll` + writes files with `os.WriteFile`, with no check whether the directory already exists and was populated by a different `owner/repo`: [1](#0-0) 

`matchSkillByName` (`pkg/cmd/skills/install/install.go:802-830`) resolves the requested name against skills discovered from the single `opts.repo` currently being installed and returns a match without ever consulting the lockfile or the filesystem for a same-named skill from a different source: [2](#0-1) 

`collisionError`/`FindNameCollisions` (`pkg/cmd/skills/install/install.go:904-911`, `internal/skills/discovery/collisions.go:21-43`) only groups skills by `Name` within the slice passed to it — i.e., skills discovered from the one repo being installed in the current invocation. It has no notion of previously-installed skills or lockfile records: [3](#0-2) [4](#0-3) 

After the write, `lockfile.RecordInstall` (`internal/skills/lockfile/lockfile.go:97-137`) looks up the existing entry only to preserve `InstalledAt`, then unconditionally replaces `Source`, `SourceType`, `SourceURL`, `SkillPath`, `SkillFolderHash`, and `PinnedRef` with the new install's values — there is no check comparing the previous `Source`/`SourceURL` against the new one, and no warning or confirmation is raised on mismatch: [5](#0-4) 

Exploit flow: victim runs `gh skill install trusted-org/trusted-repo review`, which installs to `<skills-dir>/review` and records `Source: "trusted-org/trusted-repo"` in the lockfile. An attacker later publishes `attacker/repo` containing a skill whose `Name` is also `review`. When the victim runs `gh skill install attacker/repo review`, `matchSkillByName` finds a single match (no collision, since collisions are only computed within `attacker/repo`'s own discovered skill set), `installSkill` writes into the same `<skills-dir>/review` directory (overwriting the previous SKILL.md/files), and `RecordInstall` overwrites the lockfile's `review` entry to point at `attacker/repo`, erasing any trace that the directory was previously sourced from `trusted-org/trusted-repo` (only `InstalledAt` survives).

### Impact Explanation
This is a file-overwrite-outside-intended-trust-boundary combined with wrong-repo provenance routing: a directory that an agent/tool trusts as coming from `trusted-org/trusted-repo` (e.g., a skill previously reviewed/approved by the victim) can be silently replaced by attacker content under the same on-disk path, and the lockfile — which is the source of truth for "what repo did this skill come from" for any pin/verify-by-name workflow — is falsely updated to attribute the (now attacker) content to whichever repo installed last. Any downstream tooling that trusts `.skill-lock.json` for provenance decisions (e.g., re-verification, "did this skill change source?" checks) is defeated.

### Likelihood Explanation
Requires the victim to have previously installed a skill named `review` (or any name) from a trusted repo, then be induced to run `gh skill install <attacker>/<repo> review` naming the same flat `Name`. This is a normal, expected `gh skill install` usage pattern (installing skills by name from repos), does not require any social engineering beyond the victim choosing to install from a new/attacker repo — a scenario the tool is explicitly designed to support — and is fully repeatable/deterministic.

### Recommendation
Before writing to `skillDir` in `installSkill`, check whether the directory already exists and, if so, whether the existing lockfile entry for that `Name` records a different `owner`/`repo`/`host`. If so, require `--force` or an explicit interactive confirmation naming both the old and new source, mirroring what `collisionError` already does for intra-batch collisions. Additionally, `lockfile.RecordInstall` should expose (or the caller should check) the previous `Source`/`SourceURL` and refuse/overwrite only when explicitly confirmed, rather than silently reassigning provenance.

### Proof of Concept
Go integration test sketch (extending `pkg/cmd/skills/install/install_test.go` style):
```go
func TestInstall_CrossRepoNameOverwriteNoCollisionDetected(t *testing.T) {
    dir := t.TempDir()
    // 1. Install "review" from trusted-org/trusted-repo
    optsTrusted := &InstallOptions{ SkillSource: "trusted-org/trusted-repo", SkillName: "review", Dir: dir, /* stub httpmock for trusted-org/trusted-repo tree+blob */ }
    runInstallHelper(t, optsTrusted)
    lf := readTestLockfile(t, lockPath)
    require.Equal(t, "trusted-org/trusted-repo", lf.Skills["review"].Source)

    // 2. Install "review" from attacker/repo, same flat Name
    optsAttacker := &InstallOptions{ SkillSource: "attacker/repo", SkillName: "review", Dir: dir, /* stub httpmock for attacker/repo tree+blob, different content */ }
    err := runInstallHelper(t, optsAttacker) // expect this to currently succeed with no error/prompt
    require.NoError(t, err)

    // Assert vulnerability: on-disk content silently replaced, lockfile provenance overwritten
    content, _ := os.ReadFile(filepath.Join(dir, "review", "SKILL.md"))
    assert.Contains(t, string(content), "attacker") // now attacker content
    lf2 := readTestLockfile(t, lockPath)
    assert.Equal(t, "attacker/repo", lf2.Skills["review"].Source) // provenance silently reassigned
}
```
Expected current (vulnerable) behavior: no error, no collision detected, `review` directory and lockfile entry silently switch ownership from `trusted-org/trusted-repo` to `attacker/repo`. After the fix, this should either error out or prompt for confirmation before overwriting.

### Citations

**File:** internal/skills/installer/installer.go (L251-256)
```go
func installSkill(opts *Options, skill discovery.Skill, baseDir string) error {
	// Use skill.Name (not InstallName) for a flat directory layout.
	skillDir := filepath.Join(baseDir, skill.Name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return fmt.Errorf("could not create directory %s: %w", skillDir, err)
	}
```

**File:** pkg/cmd/skills/install/install.go (L802-820)
```go
func matchSkillByName(opts *InstallOptions, skills []discovery.Skill) ([]discovery.Skill, error) {
	for _, s := range skills {
		if s.DisplayName() == opts.SkillName {
			return []discovery.Skill{s}, nil
		}
	}

	var matches []discovery.Skill
	for _, s := range skills {
		if s.Name == opts.SkillName {
			matches = append(matches, s)
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("skill %q not found in %s", opts.SkillName, ghrepo.FullName(opts.repo))
	case 1:
		return matches, nil
```

**File:** pkg/cmd/skills/install/install.go (L904-911)
```go
func collisionError(ss []discovery.Skill) error {
	collisions := discovery.FindNameCollisions(ss)
	if len(collisions) == 0 {
		return nil
	}
	return fmt.Errorf("cannot install skills with conflicting names; they would overwrite each other:\n  %s",
		discovery.FormatCollisions(collisions))
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

**File:** internal/skills/lockfile/lockfile.go (L117-136)
```go
	now := time.Now().UTC().Format(time.RFC3339)

	existing, exists := f.Skills[skillName]
	installedAt := now
	if exists {
		installedAt = existing.InstalledAt
	}

	f.Skills[skillName] = entry{
		Source:          owner + "/" + repo,
		SourceType:      "github",
		SourceURL:       ghinstance.HostPrefix(host) + owner + "/" + repo + ".git",
		SkillPath:       skillPath,
		SkillFolderHash: treeSHA,
		InstalledAt:     installedAt,
		UpdatedAt:       now,
		PinnedRef:       pinnedRef,
	}

	return writeTo(lockedFile, f)
```
