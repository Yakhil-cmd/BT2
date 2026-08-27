### Title
Sparse-checkout content restriction is bypassed by unconditional submodule checkout - (File: main.go)

### Summary
`git-sync` exposes `--sparse-checkout-file` as the only mechanism operators have to restrict which paths of an upstream repository are actually materialized into the published worktree/symlink target. However, `configureWorktree` applies the sparse-checkout configuration and then unconditionally runs `git submodule update --init [--recursive]` afterward whenever `--submodules` is not `off` (the default is `recursive`), with no interaction between the two features. This mirrors the reported minievm issue: a restriction is enforced at one "entry point" (top-level checkout governed by the sparse-checkout pattern) while an alternate internal mechanism (submodule population) is left completely unguarded, letting attacker-controlled repo content (a `.gitmodules` entry) reintroduce content the operator intended to exclude.

### Finding Description
In `configureWorktree`, the sequence is: configure sparse-checkout patterns from `--sparse-checkout-file` → `git reset --hard <hash>` (which respects the sparse pattern) → unconditional `git submodule update --init [--recursive] [--depth N]` when submodules are enabled: [1](#0-0) 

The sparse-checkout file is the operator's declared mechanism for controlling exactly which files/directories are ever written to the published worktree (analogous to `AllowedPublishers` gating who may write contract bytecode in minievm). But nothing in `configureWorktree`, `SyncRepo`, or `fetch` restricts submodule initialization/checkout to the paths selected by the sparse-checkout pattern. Since `.gitmodules` is committed content controlled by whoever can push to the tracked ref, an attacker with (or gaining) write access to the upstream repo — the same untrusted-push threat model used throughout this class of report — can add or repoint a submodule entry. `git submodule update --init --recursive` will then materialize that submodule's full content into the worktree directory tree, independent of whether that directory is excluded by the sparse-checkout pattern, just as `EVM::Create`/`Create2` bypass the msg-server-level publisher check in minievm because the restriction was only wired into one call path and not the lower-level primitive that achieves the same effect.

The e2e test suite exercises sparse-checkout and submodules as separate features but never in combination: [2](#0-1) [3](#0-2) 

confirming the interaction is untested and unguarded.

### Impact Explanation
An operator who relies on `--sparse-checkout-file` to prevent certain repository content from ever landing in the shared volume (e.g., for size control, or to keep specific paths out of the published tree available to the app container) can have that restriction silently defeated. A malicious or compromised contributor to the source repo can add a submodule pointing at an arbitrary external repository, and its content will be checked out into the worktree that consumers read via the `--link` symlink — publishing unintended/unrestricted content despite the sparse-checkout configuration. This falls under "publishing wrong or partial content."

### Likelihood Explanation
Likelihood is moderate: it requires push access to the synced ref (the standard untrusted-commit threat model for this class of report) and requires the operator to be using both `--sparse-checkout-file` and non-`off` `--submodules` (which is the default value), so any deployment using sparse-checkout without explicitly disabling submodules is exposed.

### Recommendation
When `--sparse-checkout-file` is set, either (a) default `--submodules` to `off` unless explicitly re-enabled, (b) filter submodule paths against the sparse-checkout patterns before running `git submodule update`, or (c) document and fail fast if both are configured together so operators are aware sparse-checkout does not constrain submodule content, closing the gap between the declared restriction and the actual checkout mechanism used.

### Proof of Concept
1. Operator runs `git-sync` with `--sparse-checkout-file` excluding directory `vendor/` and default `--submodules=recursive`.
2. Attacker with push access to the tracked branch commits a `.gitmodules` entry adding a submodule at path `vendor/evil` pointing to an attacker-controlled repository, then commits.
3. On next sync, `configureWorktree` applies the sparse-checkout pattern (excluding `vendor/`) via `sparse-checkout init` and `reset --hard`, then unconditionally executes `submodule update --init --recursive`: [4](#0-3) 
4. The `vendor/evil` submodule content is checked out into the worktree that gets published via `publishSymlink`, even though `vendor/` was declared excluded by the operator's sparse-checkout policy — demonstrating the restriction bypass.

### Citations

**File:** main.go (L1685-1747)
```go
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

	// Update submodules
	// NOTE: this works for repo with or without submodules.
	if git.submodules != submodulesOff {
		git.log.V(1).Info("updating submodules")
		submodulesArgs := []string{"submodule", "update", "--init"}
		if git.submodules == submodulesRecursive {
			submodulesArgs = append(submodulesArgs, "--recursive")
		}
		if git.depth != 0 {
			submodulesArgs = append(submodulesArgs, "--depth", strconv.Itoa(git.depth))
		}
		if _, _, err := git.Run(ctx, worktree.Path(), submodulesArgs...); err != nil {
			return err
		}
	}
```

**File:** test_e2e.sh (L2975-3018)
```shellscript
    assert_file_exists "$ROOT/link/file"
    assert_file_eq "$ROOT/link/file" "${FUNCNAME[0]}"
}

##############################################
# Test submodule sync
##############################################
function e2e::submodule_sync_default() {
    # Init submodule repo
    local submodule_repo_name="sub"
    local submodule="$WORK/$submodule_repo_name"
    mkdir "$submodule"

    git -C "$submodule" init -q -b "$MAIN_BRANCH"
    echo "submodule" > "$submodule/submodule.file"
    git -C "$submodule" add submodule.file
    git -C "$submodule" commit -aqm "init submodule.file"

    # Init nested submodule repo
    local nested_submodule_repo_name="nested-sub"
    local nested_submodule="$WORK/$nested_submodule_repo_name"
    mkdir "$nested_submodule"

    git -C "$nested_submodule" init -q -b "$MAIN_BRANCH"
    echo "nested-submodule" > "$nested_submodule/nested-submodule.file"
    git -C "$nested_submodule" add nested-submodule.file
    git -C "$nested_submodule" commit -aqm "init nested-submodule.file"

    # Add submodule
    git -C "$REPO" -c protocol.file.allow=always submodule add -q file://$submodule "$submodule_repo_name"
    git -C "$REPO" commit -aqm "add submodule"

    GIT_SYNC \
        --period=100ms \
        --repo="file://$REPO" \
        --root="$ROOT" \
        --link="link" \
        &
    wait_for_sync "${MAXWAIT}"
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_exists "$ROOT/link/$submodule_repo_name/submodule.file"
    assert_file_eq "$ROOT/link/$submodule_repo_name/submodule.file" "submodule"
    assert_metric_eq "${METRIC_GOOD_SYNC_COUNT}" 1
```

**File:** test_e2e.sh (L3452-3479)
```shellscript
##############################################
# Test sparse-checkout files
##############################################
function e2e::sparse_checkout() {
    echo "!/*" > "$WORK/sparseconfig"
    echo "!/*/" >> "$WORK/sparseconfig"
    echo "file2" >> "$WORK/sparseconfig"
    echo "${FUNCNAME[0]}" > "$REPO/file"
    echo "${FUNCNAME[0]}" > "$REPO/file2"
    mkdir "$REPO/dir"
    echo "${FUNCNAME[0]}" > "$REPO/dir/file3"
    git -C "$REPO" add file2
    git -C "$REPO" add dir
    git -C "$REPO" commit -qam "${FUNCNAME[0]}"

    GIT_SYNC \
        --one-time \
        --repo="file://$REPO" \
        --root="$ROOT" \
        --link="link" \
        --sparse-checkout-file="$WORK/sparseconfig"
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file2"
    assert_file_absent "$ROOT/link/file"
    assert_file_absent "$ROOT/link/dir/file3"
    assert_file_absent "$ROOT/link/dir"
    assert_file_eq "$ROOT/link/file2" "${FUNCNAME[0]}"
}
```
