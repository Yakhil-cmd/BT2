### Title
Non-atomic pinned extension install leaves an unverified/unpinned git checkout runnable as a trusted extension - ([File: pkg/cmd/extension/manager.go])

### Summary
`gh extension install owner/repo --pin <tag>` clones the repository and only afterwards checks out the pinned commit. If the checkout step fails or is interrupted after the clone succeeds, the extension directory is left on disk fully populated with the default-branch `HEAD` content instead of the user-requested pinned commit, and no `.pin-<sha>` marker or manifest is written. `Manager.list()` discovers installed git extensions purely by directory presence (`gh-` prefix + absence of a binary manifest), with no dependency on the pin marker or a completed-install marker. As a result, `gh extension exec`/`gh <ext>` can dispatch and execute this partially-installed, unpinned checkout as if it were the fully verified/pinned extension the user intended to trust.

### Finding Description
`installGit` in `pkg/cmd/extension/manager.go` performs the install as multiple independent, non-atomic steps: [1](#0-0) 

1. `m.gitClient.Clone(cloneURL, []string{targetDir})` — clones the full repository into `targetDir`, immediately populating an executable tree.
2. Only if `commitSHA != ""` does it call `scopedClient.CheckoutBranch(commitSHA)`.
3. Only after a successful checkout is the `.pin-<sha>` marker file created.

If step 2 or 3 fails (network interruption, disk error, or a transient git failure), `installGit` returns an error to the caller, but `targetDir` already exists with a full working tree checked out to whatever `HEAD` the clone resolved to (the default branch at clone time) — not the tag/commit the user asked to pin to.

Extension discovery treats this half-finished directory as a normal, fully-installed extension: [2](#0-1) 

`list()` only checks for the `gh-` prefix and whether a binary manifest exists — for git extensions there is no check for the presence of the pin marker, nor any "installation completed" sentinel. Consequently `Manager.List()` and `Manager.Dispatch()` (used by `gh <ext>` and `gh extension exec`) will happily find and execute the extension's binary/script from this directory: [3](#0-2) 

There is no "lock"/two-phase-commit around the multi-step install (clone → checkout → mark pinned), directly mirroring the reported bug class: intermediate state produced by an incomplete multi-step operation is left reachable and is treated by downstream logic as if the whole operation had completed successfully and under the intended constraints (a specific pinned, presumably reviewed/trusted commit).

### Impact Explanation
An attacker who controls (or can influence, e.g. via a compromised default branch, a race between publishing a malicious commit and the pin resolving, or simply relies on users hitting flaky network conditions) the default branch HEAD of an extension repository can have unpinned/unreviewed code execute under the extension host process the next time the user runs the affected `gh <ext>` command, even though the user explicitly requested pinning to a specific, presumably vetted, commit/tag. This is a local-code-execution-adjacent trust bypass reachable purely through normal `gh extension install --pin <target>` usage against an attacker-influenced remote repository — no privileged or local access is required beyond normal CLI use. It is analogous to the reported issue: a multi-step operation (analogous to swap execution across multiple contracts) that is not atomic, so a mid-operation failure leaves the system in a state (unpinned code present and runnable) that the caller never intended and that downstream logic (list/dispatch — analogous to onward swap use) does not detect or reject.

### Likelihood Explanation
Likelihood is moderate: it requires (a) the user to install/pin an extension whose upstream repository the attacker can influence (or a race condition around publishing malicious content right before pin resolution), and (b) a transient failure between clone and checkout (network drop, git failure, killed process) that is not entirely under attacker control. This is a real but conditional pathway; it is not guaranteed on every install, unlike an unconditional bypass. It does not require local/admin privileges or MITM.

### Recommendation
Make `installGit` atomic with respect to pinning:
- Clone/checkout into a temporary staging directory first (e.g., `targetDir + ".tmp-<random>"`).
- Perform the checkout to `commitSHA` (when pinning) inside the staging directory, and only after checkout succeeds, atomically `rename` the staging directory into `targetDir` (same pattern already used elsewhere in the codebase, e.g. `swapDirectoryContents` in `pkg/cmd/skills/update/update.go`).
- If checkout fails, remove the staging directory entirely so no partially-installed, unpinned tree is ever placed at `targetDir`.
- Have `list()`/extension discovery require a completed-install marker (or verify the recorded pin, when present, matches the extension's current `HEAD`) before treating a git extension directory as a valid, dispatchable extension.

### Proof of Concept
1. `gh extension install attacker/gh-ext --pin v1.0.0` where `attacker/gh-ext`'s default branch differs from `v1.0.0`.
2. Simulate/trigger a failure between clone and checkout (e.g., interrupt the process, or have `CheckoutBranch` fail due to network/tag deletion) — this can be reproduced by unit-testing `installGit` with a `gitClient` mock whose `CheckoutBranch` returns an error after `Clone` succeeds, as already partially set up in `pkg/cmd/extension/manager_test.go` (`TestManager_Install_git_pinned`), but asserting on state instead of just the returned error.
3. Observe: `targetDir` exists with the default-branch content, no `.pin-<sha>` file is present, `Manager.list()` returns this as an installed `GitKind` extension, and `Manager.Dispatch()` will execute it. [1](#0-0) [2](#0-1)

### Citations

**File:** pkg/cmd/extension/manager.go (L92-139)
```go
func (m *Manager) Dispatch(args []string, stdin io.Reader, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, errors.New("too few arguments in list")
	}

	var exe string
	extName := args[0]
	forwardArgs := args[1:]

	exts, _ := m.list(false)
	var ext *Extension
	for _, e := range exts {
		if e.Name() == extName {
			ext = e
			exe = ext.Path()
			break
		}
	}
	if exe == "" {
		return false, nil
	}

	var externalCmd *exec.Cmd

	if ext.IsBinary() || runtime.GOOS != "windows" {
		externalCmd = m.newCommand(exe, forwardArgs...)
	} else if runtime.GOOS == "windows" {
		// Dispatch all extension calls through the `sh` interpreter to support executable files with a
		// shebang line on Windows.
		shExe, err := m.findSh()
		if err != nil {
			if errors.Is(err, exec.ErrNotFound) {
				return true, errors.New("the `sh.exe` interpreter is required. Please install Git for Windows and try again")
			}
			return true, err
		}
		forwardArgs = append([]string{"-c", `command "$@"`, "--", exe}, forwardArgs...)
		externalCmd = m.newCommand(shExe, forwardArgs...)
	}
	// Signal to the extension that it is being run by gh rather than standalone, so it can
	// adjust things like usage strings.
	externalCmd.Env = append(externalCmd.Environ(), "GH_EXTENSION=1")

	externalCmd.Stdin = stdin
	externalCmd.Stdout = stdout
	externalCmd.Stderr = stderr
	return true, externalCmd.Run()
}
```

**File:** pkg/cmd/extension/manager.go (L150-199)
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
		} else if isSymlink(f.Type()) {
			results = append(results, &Extension{
				path: filepath.Join(dir, f.Name(), f.Name()),
				kind: LocalKind,
			})
		} else {
			// the contents of a regular file point to a local extension on disk
			p, err := readPathFromFile(filepath.Join(dir, f.Name()))
			if err != nil {
				return nil, err
			}
			results = append(results, &Extension{
				path: filepath.Join(p, f.Name()),
				kind: LocalKind,
			})
		}
	}

	if includeMetadata {
		m.populateLatestVersions(results)
	}

	return results, nil
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
