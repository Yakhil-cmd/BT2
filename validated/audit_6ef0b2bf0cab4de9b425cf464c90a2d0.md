No vulnerability found for this question.

`git-sync` never writes into `.git/hooks`, never sets `core.hooksPath` to attacker-controlled content, and never reads a repo-tracked `.gitconfig`/`.gitattributes` as global git configuration.

The relevant flow: `initRepo` runs `git init -b git-sync` in `git.root`, which is a directory git-sync creates and owns itself, not attacker content [1](#0-0) . Content sync happens via `createWorktree` (`git worktree add --force --detach ... --no-checkout`) followed by `configureWorktree`, which writes the worktree's `.git` file pointing back at `git.root/.git/worktrees/<hash>` and then runs `git reset --hard hash --` to populate tracked files [2](#0-1) . This checkout only materializes ordinary tracked files into the worktree; it does not touch `git.root/.git/hooks`, and a worktree's hooks directory is always inherited from the shared `.git/hooks` of the common repo — git itself does not let a worktree carry its own hooks directory populated from tracked content.

All git configuration that git-sync applies is written with `git config --global ...`, e.g. `SetupDefaultGitConfigs` and `SetupExtraGitConfigs`, which only accept operator-supplied `--git-config`/`--git-config-add` flags, not anything derived from repo content [3](#0-2) . There is no code path that reads a committed `.gitconfig` or `.gitattributes` file from the synced repo and applies it as global/system config, and no reference to `core.hooksPath` or `.git/hooks` anywhere in the codebase (`grep` for `hooksPath|\.git/hooks|CopyHooks|installHook` returns no matches). The only "hooks" concepts in git-sync are its own `--exechook-command` and `--webhook-*` mechanisms, implemented in `pkg/hook/exechook.go` and `pkg/hook/webhook.go`, which are explicit operator-configured commands/URLs, not automatically invoked git hook scripts derived from repo content [4](#0-3) .

Since the attacker only controls repo content/refs (not flags, mounts, or the `--root` volume's `.git` directory contents outside of what `git init`/`git worktree` create), there is no reachable path by which a committed `post-checkout`/`post-merge` script or a committed `.gitconfig` setting `core.hooksPath` becomes active during git-sync's fetch/checkout/reset sequence.

### Citations

**File:** main.go (L1389-1398)
```go
	if needGitInit {
		// Running `git init` in an existing repo is safe (according to git docs).
		git.log.V(0).Info("initializing repo directory", "path", git.root)
		if _, _, err := git.Run(ctx, git.root, "init", "-b", "git-sync"); err != nil {
			return err
		}
		if !git.sanityCheckRepo(ctx) {
			return fmt.Errorf("can't initialize git repo directory")
		}
	}
```

**File:** main.go (L1642-1731)
```go
// createWorktree creates a new worktree and checks out the given hash.  This
// returns the path to the new worktree.
func (git *repoSync) createWorktree(ctx context.Context, hash string) (worktree, error) {
	// Make a worktree for this exact git hash.
	worktree := git.worktreeFor(hash)

	// Avoid wedge cases where the worktree was created but this function
	// error'd without cleaning up.  The next time thru the sync loop fails to
	// create the worktree and bails out. This manifests as:
	//     "fatal: '/repo/root/nnnn' already exists"
	if err := git.removeWorktree(ctx, worktree); err != nil {
		return "", err
	}

	git.log.V(1).Info("adding worktree", "path", worktree.Path(), "hash", hash)
	_, _, err := git.Run(ctx, git.root, "worktree", "add", "--force", "--detach", worktree.Path().String(), hash, "--no-checkout")
	if err != nil {
		return "", err
	}

	return worktree, nil
}

// configureWorktree applies some configuration (e.g. sparse checkout) to
// the specified worktree and checks out the specified hash and submodules.
func (git *repoSync) configureWorktree(ctx context.Context, worktree worktree) error {
	hash := worktree.Hash()

	// The .git file in the worktree directory holds a reference to
	// /git/.git/worktrees/<worktree-dir-name>. Replace it with a reference
	// using relative paths, so that other containers can use a different volume
	// mount name.
	var rootDotGit string
	if rel, err := filepath.Rel(worktree.Path().String(), git.root.String()); err != nil {
		return err
	} else {
		rootDotGit = filepath.Join(rel, ".git")
	}
	gitDirRef := []byte("gitdir: " + filepath.Join(rootDotGit, "worktrees", hash) + "\n")
	if err := os.WriteFile(worktree.Path().Join(".git").String(), gitDirRef, 0644); err != nil {
		return err
	}

	// If sparse checkout is requested, configure git for it, otherwise
	// unconfigure it.
	gitInfoPath := filepath.Join(git.root.String(), ".git/worktrees", hash, "info")
	gitSparseConfigPath := filepath.Join(gitInfoPath, "sparse-checkout")
	if git.sparseFile == "" {
		os.RemoveAll(gitSparseConfigPath)
	} else {
		// This is required due to the undocumented behavior outlined here:
		// https://public-inbox.org/git/CAPig+cSP0UiEBXSCi7Ua099eOdpMk8R=JtAjPuUavRF4z0R0Vg@mail.gmail.com/t/
		git.log.V(1).Info("configuring worktree sparse checkout")
		checkoutFile := git.sparseFile

		source, err := os.Open(checkoutFile)
		if err != nil {
			return err
		}
		defer source.Close()

		if _, err := os.Stat(gitInfoPath); os.IsNotExist(err) {
			err := os.Mkdir(gitInfoPath, defaultDirMode)
			if err != nil {
				return err
			}
		}

		destination, err := os.Create(gitSparseConfigPath)
		if err != nil {
			return err
		}
		defer destination.Close()

		_, err = io.Copy(destination, source)
		if err != nil {
			return err
		}

		args := []string{"sparse-checkout", "init"}
		if _, _, err = git.Run(ctx, worktree.Path(), args...); err != nil {
			return err
		}
	}

	// Reset the worktree's working copy to the specific ref.
	git.log.V(1).Info("setting worktree HEAD", "hash", hash)
	if _, _, err := git.Run(ctx, worktree.Path(), "reset", "--hard", hash, "--"); err != nil {
		return err
	}
```

**File:** main.go (L2276-2320)
```go
// SetupDefaultGitConfigs configures the global git environment with some
// default settings that we need.
func (git *repoSync) SetupDefaultGitConfigs(ctx context.Context) error {
	configs := []keyVal{{
		// Never auto-detach GC runs.
		key: "gc.autoDetach",
		val: "false",
	}, {
		// Fairly aggressive GC.
		key: "gc.pruneExpire",
		val: "now",
	}, {
		// How to manage credentials (for those modes that need it).
		key: "credential.helper",
		val: "cache --timeout 3600",
	}, {
		// Never prompt for a password.
		key: "core.askPass",
		val: "true",
	}}

	for _, kv := range configs {
		if _, _, err := git.Run(ctx, "", "config", "--global", kv.key, kv.val); err != nil {
			return fmt.Errorf("error configuring git %q %q: %w", kv.key, kv.val, err)
		}
	}
	return nil
}

// SetupExtraGitConfigs configures the global git environment with user-provided
// override settings.
func (git *repoSync) SetupExtraGitConfigs(ctx context.Context, configsFlag string, flagName string) error {
	configs, err := parseGitConfigs(configsFlag)
	if err != nil {
		return fmt.Errorf("can't parse %s flag: %w", flagName, err)
	}
	git.log.V(1).Info("setting additional git configs", "configs", configs)
	for _, kv := range configs {
		if _, _, err := git.Run(ctx, "", "config", "--global", kv.key, kv.val); err != nil {
			return fmt.Errorf("error configuring additional git configs %q %q: %w", kv.key, kv.val, err)
		}
	}

	return nil
}
```

**File:** pkg/hook/exechook.go (L64-80)
```go
// Do runs exechook.command, implements Hook.Do.
func (h *Exechook) Do(ctx context.Context, hash string) error {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	worktreePath := h.getWorktree(hash)

	env := os.Environ()
	env = append(env, envKV("GITSYNC_HASH", hash))

	h.log.V(0).Info("running exechook", "hash", hash, "command", h.command, "timeout", h.timeout)
	stdout, stderr, err := h.cmdrunner.Run(ctx, worktreePath, env, h.command, h.args...)
	if err == nil {
		h.log.V(1).Info("exechook succeeded", "hash", hash, "stdout", stdout, "stderr", stderr)
	}
	return err
}
```
