### Title
Symlink-based path traversal write during `gh extension` binary migration - (File: pkg/cmd/extension/http.go)

### Summary
`gh`'s extension manager reuses the same on-disk extension directory across install methods (script/git-based vs. release-binary-based). The binary-asset writer opens the destination file with `O_TRUNC` and no `O_EXCL`/symlink check, so if that path is already a symlink — which can be planted by content that `git clone` materialized from an attacker-controlled extension repository — the write follows the symlink outside the extensions directory. This mirrors the `harp` report's bug class: content controlled by an untrusted, attacker-published source (a symlink) is silently followed during a write, producing a path-traversal file write instead of a read.

### Finding Description
`downloadAsset` writes a downloaded GitHub Release asset to `destPath` using: [1](#0-0) 
`os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)` follows an existing symlink at `destPath` rather than refusing to write through it (no `O_EXCL`, no `lstat`/symlink check as is done elsewhere in the codebase, e.g. `pkg/cmd/repo/read-file/read_file.go`).

`destPath` is computed as `targetDir/name(+ext)` in `installBin`: [2](#0-1) 
`targetDir` is created with `os.MkdirAll`, which is a no-op if the directory already exists — it does not remove pre-existing files.

Critically, an extension can first be installed as a git/script extension via `installGit`, which runs `git clone` directly into `targetDir`: [3](#0-2) 
Because `hasScript` requires the repository to contain a file at `contents/<repo-name>` — the exact same filename later used as the binary path (`name` or `name+ext`) — a malicious extension author can commit that required file as a **symlink** (e.g. pointing at `../../.ssh/authorized_keys`, `../../.gitconfig`, or another path outside the extension directory) instead of a regular script. `git clone` on Linux/macOS (where `core.symlinks` defaults to true) materializes this as a real filesystem symlink.

If the same repository later publishes a GitHub Release (making it eligible for `installBin`), a subsequent `gh extension upgrade` transitions the extension from git-based to binary-based install (this exact migration is exercised by `TestManager_MigrateToBinaryExtension`): [4](#0-3) 
`installBin` then calls `downloadAsset(..., binPath)` where `binPath` is identical to the path of the symlink left behind by the earlier `git clone`. Because the directory isn't wiped and the writer follows symlinks, the release-asset bytes are written through the symlink to whatever file it targets, outside the intended extension directory.

### Impact Explanation
An unprivileged, remote attacker (the publisher of a third-party `gh` extension the victim installs and later upgrades with `gh extension upgrade`) can overwrite an arbitrary file reachable by the user running `gh`, using content the attacker fully controls. Depending on the target chosen for the symlink, this can lead to configuration tampering, SSH `authorized_keys` injection, or overwriting files that are later executed/trusted, resulting in code execution or credential compromise.

### Likelihood Explanation
Requires the victim to (1) install a third-party extension, and (2) run `gh extension upgrade` after the malicious author publishes a release turning it from a script extension into a binary extension — this is a normal, expected `gh` extension lifecycle action and is explicitly covered by existing test scenarios in the codebase, so the migration path is a supported and reachable feature rather than a corner case. The attacker needs no privileges beyond publishing content to their own repository, matching the "unprivileged remote attacker" and "extension install/execution" categories in scope.

### Recommendation
In `downloadAsset` (`pkg/cmd/extension/http.go`), refuse to write through an existing symlink at `destPath` — e.g., `lstat` the destination first and error out if it is a symlink, or open with `O_EXCL` after removing any pre-existing non-regular file, consistent with the symlink guard already implemented in `pkg/cmd/repo/read-file/read_file.go`'s `writeToOutput`. Additionally, `installBin`/`installGit` should fully clear (`os.RemoveAll` then recreate) `targetDir` before writing new content when transitioning between install types, rather than relying on non-destructive `MkdirAll`.

### Proof of Concept
1. Attacker publishes `owner/gh-evil` containing a file named `gh-evil` at the repo root that is a **symlink** to `~/.ssh/authorized_keys` (satisfies `hasScript`'s check at `pkg/cmd/extension/http.go:45-66`).
2. Victim runs `gh extension install owner/gh-evil` → `installGit` clones the repo, materializing the symlink at `<extDir>/gh-evil/gh-evil`. [5](#0-4) 
3. Attacker later publishes a GitHub Release with an asset for the victim's platform, so `isBinExtension` now returns true.
4. Victim runs `gh extension upgrade owner/gh-evil` → `installBin` computes `binPath = <extDir>/gh-evil/gh-evil` and calls `downloadAsset`, which opens that path with `O_TRUNC` and follows the symlink, overwriting `~/.ssh/authorized_keys` with attacker-controlled release-asset bytes. [6](#0-5)

### Citations

**File:** pkg/cmd/extension/http.go (L100-111)
```go
	var f *os.File
	if f, downloadErr = os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755); downloadErr != nil {
		return
	}
	defer func() {
		if err := f.Close(); downloadErr == nil && err != nil {
			downloadErr = err
		}
	}()

	_, downloadErr = io.Copy(f, resp.Body)
	return
```

**File:** pkg/cmd/extension/manager.go (L341-356)
```go
	name := repo.RepoName()
	if err := m.cleanExtensionUpdateDir(name); err != nil {
		return err
	}

	targetDir := filepath.Join(m.installDir(), name)
	if err = os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create installation directory: %w", err)
	}

	binPath := filepath.Join(targetDir, name)
	binPath += ext

	err = downloadAsset(m.client, safeurl.NewImmutableSafeURL(asset.APIURL), binPath)
	if err != nil {
		return fmt.Errorf("failed to download asset %s: %w", asset.Name, err)
```

**File:** pkg/cmd/extension/manager.go (L412-435)
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
```

**File:** pkg/cmd/extension/manager_test.go (L510-524)
```go
func TestManager_MigrateToBinaryExtension(t *testing.T) {
	dataDir := t.TempDir()
	updateDir := t.TempDir()
	assert.NoError(t, stubExtension(filepath.Join(dataDir, "extensions", "gh-remote", "gh-remote")))
	ios, _, stdout, stderr := iostreams.Test()

	reg := httpmock.Registry{}
	defer reg.Verify(t)
	client := http.Client{Transport: &reg}
	gc := &gitExecuter{client: &git.Client{}}

	m := newTestManager(dataDir, updateDir, &client, gc, ios)
	exts, err := m.list(false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(exts))
```
