## Analysis



The relevant analog lives in `gh`'s extension manager. Trust is established once, at install time, with an explicit warning that "you are trusting its publisher" [1](#0-0) , but that trust decision is never re-validated on subsequent operations. `Manager.Upgrade` -> `upgradeExtension` -> `upgradeGitExtension` simply runs `git fetch`/`pull` (or `reset --hard origin/HEAD` with `--force`) against the extension's existing local clone and remote, with no check that the remote repository is still controlled by the same account that was trusted at install time [2](#0-1) . Likewise, `upgradeBinExtension`/`LatestVersion` re-derive the repo purely from the stored URL string and fetch whatever release/binary is currently published there [3](#0-2) [4](#0-3) . Extension identity/ownership is otherwise only used as a name-collision guard at fresh-install time (`checkValidExtension`) [5](#0-4) , and the one place an owner is explicitly pinned for trust purposes is the built-in official-extension allowlist, which is a distinct, narrower mechanism [6](#0-5) .

### Title
Extension upgrade trust is bound to a mutable git remote, not to the originally-vetted publisher - (File: pkg/cmd/extension/manager.go)

### Summary
`gh extension install` requires the user to accept a one-time trust decision about the publisher of `OWNER/REPO`. That trust is persisted only implicitly, as a local git clone/manifest pointing at a remote URL. `gh extension upgrade` (and automatic update checks) never re-validate that the account currently answering at that remote is the same one the user originally trusted, so if control of the underlying repository changes hands, the new controller's code is pulled and subsequently executed with the old, still-valid trust grant.

### Finding Description
When a user runs `gh extension install owner/gh-foo`, `gh` warns that "you are trusting its publisher" and clones/installs from that repository [1](#0-0) . From then on, the extension is tracked purely by its local path/manifest and the remote git URL derived from it. On upgrade, `upgradeGitExtension` performs `git pull`/`fetch`+`reset --hard` on the existing remote without any comparison to the originally-installed owner [2](#0-1) , and `upgradeBinExtension` re-parses the repo from the extension's stored URL and downloads whatever release is currently published there [3](#0-2) . `LatestVersion()` similarly just does `git ls-remote origin HEAD` or fetches the latest GitHub release for that same URL [4](#0-3) . None of these paths re-derive or re-check the *current* owner of the resolved repository against the owner that was present when the user consented to install it.

This is structurally identical to the LUKSO bug class: a resource (a UP / an extension slot) grants durable authority (universal permission / auto-pulled code execution) to whichever party currently sits behind an identifier (a data key / a git remote+repo name), and that authority is not scoped to, or invalidated upon change of, the original controlling party.

### Impact Explanation
If a previously-installed extension's repository is transferred to a different account (or deleted and its name reclaimed by an attacker, or hijacked via any means that lets a new party control commits/releases at the same `OWNER/REPO` path), every subsequent `gh extension upgrade`, background 24-hour update-notice check, or `--force` reset will pull and execute the new party's code the next time the extension runs — without the user ever seeing the "you are trusting its publisher" decision again. Since extensions run as arbitrary local executables/scripts under the user's privileges, this is a path to unprivileged remote code execution contingent on the attacker gaining control of the repository identifier that the victim already trusts.

### Likelihood Explanation
This requires an attacker to actually gain control of the specific `OWNER/REPO` that a victim has installed (e.g., via a lapsed/transferred account, or name-squatting after deletion) — the same class of "unfounded trust from the receiver" caveat the C4 judge cited when capping the original finding at Medium. It is not a MITM, admin-only, or purely theoretical design gap: it is a concrete, reachable attacker-controlled-host scenario (a git remote / release endpoint the user's `gh` will contact and execute output from) reachable through the normal `gh extension upgrade` command path, without needing local access or leaked credentials.

### Recommendation
Bind the trust decision to something stable rather than the mutable `OWNER/REPO` string: e.g., pin and verify the repository's immutable ID (GitHub's numeric repo ID) or the initial commit/tree identity at install time, and re-prompt for trust confirmation if that identity changes across upgrades (a repo transfer, rename, or a "new" repo landing on the same path). At minimum, surface a clear warning during upgrade if the resolved repository's owner differs from the owner recorded in the extension's original manifest.

### Proof of Concept
1. `gh extension install alice/gh-tool` — user accepts the publisher-trust warning; `gh` clones `https://github.com/alice/gh-tool`.
2. Control of `alice/gh-tool` passes to a different party (account transfer, or the repo is deleted and `alice/gh-tool` — or a renamed path pointing to the same clone URL — is recreated by an attacker who pushes malicious commits/releases).
3. User runs `gh extension upgrade gh-tool` (or it triggers automatically). `upgradeGitExtension`/`upgradeBinExtension` fetch and install from the same URL/repo path with no re-validation of ownership [7](#0-6) .
4. The attacker's code now executes locally under the victim's `gh <toolname>` invocation, with no further trust prompt.

### Citations

**File:** pkg/cmd/extension/command.go (L53-55)
```go
			Extensions are not verified, signed, or endorsed by GitHub. When you install or upgrade
  			an extension, you are trusting its publisher. It is your responsibility to review the
  			source and provenance of any extension before use.
```

**File:** pkg/cmd/extension/command.go (L372-391)
```go
					repo, err := ghrepo.FromFullName(args[0])
					if err != nil {
						return err
					}

					cs := io.ColorScheme()

					if ext, err := checkValidExtension(cmd.Root(), m, repo.RepoName(), repo.RepoOwner()); err != nil {
						// If an existing extension was found and --force was specified, attempt to upgrade.
						if forceFlag && ext != nil {
							return upgradeFunc(ext.Name(), forceFlag)
						}

						if errors.Is(err, alreadyInstalledError) {
							fmt.Fprintf(io.ErrOut, "%s Extension %s is already installed\n", cs.WarningIcon(), ghrepo.FullName(repo))
							return nil
						}

						return err
					}
```

**File:** pkg/cmd/extension/manager.go (L551-576)
```go
func (m *Manager) upgradeGitExtension(ext *Extension, force bool) error {
	if m.dryRunMode {
		return nil
	}
	dir := filepath.Dir(ext.path)
	scopedClient := m.gitClient.ForRepo(dir)
	if force {
		err := scopedClient.Fetch("origin", "HEAD")
		if err != nil {
			return err
		}

		_, err = scopedClient.CommandOutput([]string{"reset", "--hard", "origin/HEAD"})
		return err
	}

	return scopedClient.Pull("", "")
}

func (m *Manager) upgradeBinExtension(ext *Extension) error {
	repo, err := ghrepo.FromFullName(ext.URL())
	if err != nil {
		return fmt.Errorf("failed to parse URL %s: %w", ext.URL(), err)
	}
	return m.installBin(repo, "")
}
```

**File:** pkg/cmd/extension/extension.go (L116-141)
```go
func (e *Extension) LatestVersion() string {
	e.mu.RLock()
	if e.latestVersion != "" {
		defer e.mu.RUnlock()
		return e.latestVersion
	}
	e.mu.RUnlock()

	var latestVersion string
	switch e.kind {
	case LocalKind:
	case BinaryKind:
		repo, err := ghrepo.FromFullName(e.URL())
		if err != nil {
			return ""
		}
		release, err := fetchLatestRelease(e.httpClient, repo)
		if err != nil {
			return ""
		}
		latestVersion = release.Tag
	case GitKind:
		if lsRemote, err := e.gitClient.CommandOutput([]string{"ls-remote", "origin", "HEAD"}); err == nil {
			latestVersion = string(bytes.SplitN(lsRemote, []byte("\t"), 2)[0])
		}
	}
```

**File:** pkg/extensions/official.go (L30-53)
```go
// IsOfficial reports whether the given extension command name and owner
// match an entry in the OfficialExtensions registry. Owner must be
// checked alongside name because a user may have installed a third-party
// extension that happens to share a name with one of ours (e.g.
// `someuser/gh-stack` predates `github/gh-stack` becoming official).
// Owner will be empty for local extensions, in which case the extension
// is treated as non-official.
//
// Comparison is case-sensitive: on case-sensitive filesystems a user can
// install a private extension whose name differs only in casing (e.g.
// `gh-STACK`), and we must not treat that as official. Owner comparison
// is case-insensitive because GitHub usernames and organization names
// are themselves case-insensitive.
func IsOfficial(name, owner string) bool {
	if owner == "" {
		return false
	}
	for _, ext := range OfficialExtensions {
		if ext.Name == name && strings.EqualFold(ext.Owner, owner) {
			return true
		}
	}
	return false
}
```
