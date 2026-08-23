### Title
Git extension misclassified as Binary via committed `manifest.yml` file, bypassing pin-protection on upgrade - (File: pkg/cmd/extension/manager.go)

### Summary
`(*Manager).list` decides `GitKind` vs `BinaryKind` purely by checking whether a file named `manifest.yml` exists inside the extension's installed directory [1](#0-0) . Because that directory is the git working tree for git-installed extensions, an attacker who controls the extension's repository can commit a top-level file literally named `manifest.yml`, causing `gh` to reclassify a `GitKind` extension as `BinaryKind` on every subsequent `list()`/`Upgrade()` call.

### Finding Description
`installGit` clones the attacker's repo into `targetDir` and, if the user pinned to a commit, checks out that commit and drops a `.pin-<sha>` marker file to protect the pin [2](#0-1) . Pin enforcement for git extensions is implemented in `(*Extension).IsPinned`, which for `GitKind` looks for that `.pin-<sha>` file on disk, but for `BinaryKind` instead trusts the `IsPinned` field parsed from `manifest.yml` via `loadManifest()` [3](#0-2) .

`(*Manager).list` determines the kind solely via `os.Stat(filepath.Join(dir, f.Name(), manifestName))`, with no verification that the directory is actually a binary-extension install (e.g. no check for absence of a `.git` directory, no ownership/authenticity check on the file) [4](#0-3) . If the attacker's repo contains a file at the repo root named `manifest.yml` (optionally crafted with `IsPinned: false` or omitting the field, since Go's YAML unmarshaling defaults booleans to `false`), the next time `gh` runs `list()` this extension will be classified `BinaryKind` instead of `GitKind`.

Once misclassified, `(*Extension).IsPinned()` reads the attacker-authored `manifest.yml` instead of checking for the `.pin-<sha>` marker file that `installGit` created to protect the user's explicit pin. `upgradeExtension` then also takes the `IsBinary()` branch, calling `upgradeBinExtension` instead of the git-based `upgradeGitExtension` codepath [5](#0-4) . This lets an attacker who pushes a later malicious commit (adding `manifest.yml`) neutralize the pin protection: a user who deliberately ran `gh extension install owner/repo @ <trusted-sha>` to lock the extension to a reviewed commit will have `pinnedExtensionUpgradeError` silently skipped on the next `gh extension upgrade`, because `IsPinned()` no longer consults the `.pin-<sha>` file.

### Impact Explanation
This is a verification/authorization-bypass of the pinning safety feature intended to let users lock an extension to an audited commit. An attacker who compromises or controls the extension's upstream repo (which they already do, being its publisher) can cause a previously pinned installation to silently become "unpinned" from `gh`'s perspective, allowing `gh extension upgrade` (without `--force`) to move the user onto a newer, attacker-chosen commit that the user explicitly tried to avoid by pinning. It does not directly grant remote code execution beyond what installing/running the extension already implies, but it defeats a security control (`pinnedExtensionUpgradeError`) the user relied on to prevent automatic drift to unreviewed code.

### Likelihood Explanation
Requires only that the attacker's own repository (already trusted enough for the victim to have installed it, pinned to a specific commit) contain a root-level file literally named `manifest.yml`. No special privileges, tokens, or MITM are needed — this is fully within an unprivileged repo owner's control. The victim must run `gh extension upgrade` (or `gh extension upgrade --all`) afterward, which is a normal, expected action.

### Recommendation
Do not use presence of a same-named file as the sole discriminator between `GitKind` and `BinaryKind`. Instead, positively identify git installs (e.g., check for a `.git` directory/file in the extension directory) before falling back to binary-manifest detection, or record the extension kind explicitly at install time (e.g., a state file written by `gh` itself, not derived from attacker-controlled repository contents) and consult that record in `list()` rather than re-deriving it from `os.Stat` on repo-controlled paths.

### Proof of Concept
```go
func TestManager_List_GitExtensionMisclassifiedByManifestFile(t *testing.T) {
    dataDir := t.TempDir()
    extDir := filepath.Join(dataDir, "extensions", "gh-evil")
    require.NoError(t, os.MkdirAll(extDir, 0755))
    // Simulate installGit's clone: a .git dir plus a pin file from a pinned install
    require.NoError(t, os.MkdirAll(filepath.Join(extDir, ".git"), 0755))
    require.NoError(t, os.WriteFile(filepath.Join(extDir, ".pin-deadbeef"), []byte(""), 0600))
    // Attacker-committed file matching manifestName, placed at repo root by a later commit
    require.NoError(t, os.WriteFile(filepath.Join(extDir, "manifest.yml"), []byte("owner: evil\nname: gh-evil\nhost: github.com\ntag: v1\nispinned: false\n"), 0600))
    require.NoError(t, os.WriteFile(filepath.Join(extDir, "gh-evil"), []byte("#!/bin/sh"), 0755))

    m := newTestManager(dataDir, t.TempDir(), nil, &mockGitClient{}, nil)
    exts, err := m.list(false)
    require.NoError(t, err)
    require.Len(t, exts, 1)
    // BUG: classified as BinaryKind despite being a git-cloned, pinned install
    assert.Equal(t, GitKind, exts[0].kind, "extension should remain GitKind; pin file (.pin-deadbeef) proves git install, but list() misclassified it as BinaryKind due to attacker-committed manifest.yml")
}
```
Expected (buggy) result: `exts[0].kind == BinaryKind`, and a follow-up call to `exts[0].IsPinned()` returns `false` (from the attacker's `manifest.yml`) instead of `true` (from the presence of `.pin-deadbeef`), demonstrating the pin-bypass.

### Citations

**File:** pkg/cmd/extension/manager.go (L150-175)
```go
func (m *Manager) list(includeMetadata bool) ([]*Extension, error) {
	dir := m.installDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	results := make([]*Extension, 0, len(entries))
	for _, f := range entries {
		if !strings.HasPrefix(f.Name(), "gh-") {
			continue
		}
		if f.IsDir() {
			if _, err := os.Stat(filepath.Join(dir, f.Name(), manifestName)); err == nil {
				results = append(results, &Extension{
					path:       filepath.Join(dir, f.Name(), f.Name()),
					kind:       BinaryKind,
					httpClient: m.client,
				})
			} else {
				results = append(results, &Extension{
					path:      filepath.Join(dir, f.Name(), f.Name()),
					kind:      GitKind,
					gitClient: m.gitClient.ForRepo(filepath.Join(dir, f.Name())),
				})
			}
```

**File:** pkg/cmd/extension/manager.go (L412-452)
```go
func (m *Manager) installGit(repo ghrepo.Interface, target string) error {
	protocol := m.config.GitProtocol(repo.RepoHost()).Value
	cloneURL := ghrepo.FormatRemoteURL(repo, protocol)

	var commitSHA string
	if target != "" {
		var err error
		commitSHA, err = fetchCommitSHA(m.client, repo, target)
		if err != nil {
			return err
		}
	}

	name := strings.TrimSuffix(path.Base(cloneURL), ".git")
	targetDir := filepath.Join(m.installDir(), name)

	if err := m.cleanExtensionUpdateDir(name); err != nil {
		return err
	}

	_, err := m.gitClient.Clone(cloneURL, []string{targetDir})
	if err != nil {
		return err
	}
	if commitSHA == "" {
		return nil
	}

	scopedClient := m.gitClient.ForRepo(targetDir)
	err = scopedClient.CheckoutBranch(commitSHA)
	if err != nil {
		return err
	}

	pinPath := filepath.Join(targetDir, fmt.Sprintf(".pin-%s", commitSHA))
	f, err := os.OpenFile(pinPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to create pin file in directory: %w", err)
	}
	return f.Close()
}
```

**File:** pkg/cmd/extension/manager.go (L520-548)
```go
func (m *Manager) upgradeExtension(ext *Extension, force bool) error {
	if ext.IsLocal() {
		return localExtensionUpgradeError
	}
	if !force && ext.IsPinned() {
		return pinnedExtensionUpgradeError
	}
	if !ext.UpdateAvailable() {
		return upToDateError
	}
	var err error
	if ext.IsBinary() {
		err = m.upgradeBinExtension(ext)
	} else {
		// Check if git extension has changed to a binary extension
		var isBin bool
		repo, repoErr := repoFromPath(m.gitClient, filepath.Join(ext.Path(), ".."))
		if repoErr == nil {
			isBin, _ = isBinExtension(m.client, repo)
		}
		if isBin {
			if err := m.Remove(ext.Name()); err != nil {
				return fmt.Errorf("failed to migrate to new precompiled extension format: %w", err)
			}
			return m.installBin(repo, "")
		}
		err = m.upgradeGitExtension(ext, force)
	}
	return err
```

**File:** pkg/cmd/extension/extension.go (L150-180)
```go
func (e *Extension) IsPinned() bool {
	e.mu.RLock()
	if e.isPinned != nil {
		defer e.mu.RUnlock()
		return *e.isPinned
	}
	e.mu.RUnlock()

	var isPinned bool
	switch e.kind {
	case LocalKind:
	case BinaryKind:
		if manifest, err := e.loadManifest(); err == nil {
			isPinned = manifest.IsPinned
		}
	case GitKind:
		extDir := filepath.Dir(e.path)
		pinPath := filepath.Join(extDir, fmt.Sprintf(".pin-%s", e.CurrentVersion()))
		if _, err := os.Stat(pinPath); err == nil {
			isPinned = true
		} else {
			isPinned = false
		}
	}

	e.mu.Lock()
	e.isPinned = &isPinned
	e.mu.Unlock()

	return *e.isPinned
}
```
