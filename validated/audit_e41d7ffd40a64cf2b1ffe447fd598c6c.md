### Title
Submodule URLs from synced (attacker-influenced) repo content are treated as trusted destinations and receive git-sync's configured credentials/SSH keys without verification - (File: main.go)

### Summary
`git-sync` fetches submodules found in `.gitmodules` of the synced repository by default (`--submodules=recursive`), and applies the operator-configured authentication material (SSH keys, HTTP credentials/askpass tokens) globally to whatever host each submodule URL points to. The submodule URL is untrusted content that comes from the remote repo itself, not from an operator-approved allowlist. This mirrors the reported bug class: an operation is unconditionally treated as "trusted"/verified (there, CIF for any treasurer withdrawal destination; here, credentialed git fetches for any submodule destination) instead of being restricted to a verified target.

### Finding Description
`repoSync.configureWorktree()` unconditionally runs `git submodule update --init [--recursive]` whenever `git.submodules != submodulesOff`, which is the default (`--submodules` defaults to `"recursive"`): [1](#0-0) [2](#0-1) 

The submodule URLs are read from `.gitmodules`, which is part of the synced repository's content — i.e., content controlled by whoever can push to (or influence, e.g. via a compromised upstream, MITM without pinned known_hosts, or a malicious PR merged upstream) the `--repo` being synced. There is no allowlist or same-origin check comparing submodule remote URLs against the configured `--repo` host before git-sync executes the submodule fetch.

Authentication material configured for the primary `--repo` is applied broadly:
- SSH: All configured `--ssh-key-file` keys are made available to the ssh client (`GIT_SSH_COMMAND -i key1 -i key2 -i key3`), and are offered to *whatever host* git connects to, including submodule hosts named in `.gitmodules`, as demonstrated by the multi-key/multi-host submodule e2e test: [3](#0-2) 
- HTTP credentials: the README explicitly acknowledges that submodules may need separate credentials and provides `--credential` per-URL as the *recommended* mitigation, implying that without it, the primary repo's stored credential/askpass answer is the only credential material available and could be attempted against submodule URLs: [4](#0-3) [5](#0-4) 

This is the direct analog of the CIF bug: a trust/verification step ("this fetch target is the brokerage/approved destination") is skipped, and a privileged capability (credentialed git fetch, private key usage) is extended to *any* address supplied by untrusted input (the synced repo's `.gitmodules`) rather than being scoped to a verified destination.

### Impact Explanation
- SSH keys configured for the intended `--repo` host are offered during authentication attempts to arbitrary hosts named in submodule URLs embedded in synced (potentially attacker-controlled) content. Even though this doesn't hand over the raw private key, it discloses that the key is being used for that connection to an attacker-controlled host and, depending on SSH/known-hosts configuration, can enable credential/token misuse or interception.
- If `--askpass-url`/`--username`+`--password` are the only credentials configured (no per-URL `--credential` entries), whatever mechanism supplies credentials may be invoked/attempted against submodule hosts not intended by the operator, since git-sync does not verify the submodule URL against an approved set before running `submodule update`.
- Practically, this allows an attacker who can influence the synced repository's content (e.g., a malicious commit/PR later merged, or the referenced git ref) to redirect part of the sync's network/credential surface to an attacker-controlled destination, and to have that attacker-controlled content published into the atomic `--link` output as if it were part of the trusted upstream.

### Likelihood Explanation
Requires `--submodules` to not be set to `off` (the default is `"recursive"`), and requires an attacker who can introduce/modify a `.gitmodules` entry in content that git-sync eventually syncs (e.g. a malicious commit reachable via the configured `--ref`). This is a realistic scenario for any git-sync deployment pulling from a repo where write access is broader than the git-sync operator's trust boundary (e.g., PR-based workflows, shared repos), matching the "attacker-pushed commit" trigger required by the validation rules.

### Recommendation
- Do not implicitly extend the primary `--repo`'s credentials/SSH keys to submodule fetch targets. Require an explicit allowlist (e.g., via `--credential` URL matching) before allowing submodule fetches to succeed with configured credentials, and fail closed for uncredentialed/unlisted hosts.
- Consider validating that submodule URLs share the same origin/host as `--repo` unless the operator explicitly opts in to cross-host submodules.
- Document clearly that `--submodules=recursive` (the default) trusts arbitrary hosts named in synced `.gitmodules` content, and that operators syncing from repos with untrusted write access should set `--submodules=off` or provide a full credential allowlist.

### Proof of Concept
1. Deploy git-sync with default settings (`--submodules` unset ⇒ `recursive`) against a repo where an attacker can add a commit (e.g., via a merged PR) that adds a `.gitmodules` entry pointing to an attacker-controlled `ssh://` or `http(s)://` host.
2. Configure git-sync with `--ssh-key-file` (or `--credential`/`--askpass-url`) intended only for the legitimate `--repo` host.
3. On next sync, `configureWorktree()` executes `git submodule update --init --recursive`, which causes git to attempt to connect to the attacker-controlled submodule host using the locally configured SSH keys / credential helpers, as shown by the existing e2e test harness pattern for multi-host submodules: [6](#0-5) 
4. The attacker-controlled host observes the authentication attempt (key usage) and the fetched submodule content is checked out and published via the atomic symlink alongside the trusted content: [7](#0-6)

### Citations

**File:** main.go (L182-184)
```go
	flSubmodules := pflag.String("submodules",
		envString("recursive", "GITSYNC_SUBMODULES", "GIT_SYNC_SUBMODULES"),
		"git submodule behavior: one of 'recursive', 'shallow', or 'off'")
```

**File:** main.go (L1733-1747)
```go
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

**File:** main.go (L1947-1963)
```go
		// If we have a new hash, update the symlink to point to the new worktree.
		if changed {
			// If the previous run crashed before publishing the link, then we
			// must call the pre-publish hook, and since changed is true, we will.
			// we will. If the previous run crashed after publishing the link,
			// then we do not need to call the pre-publish hook, and since
			// changed is false, we won't. The post-publish hooks are called in
			// both cases.
			err := syncHooks.beforePublish(newWorktree.Hash())
			if err != nil {
				return false, "", err
			}

			err = git.publishSymlink(newWorktree)
			if err != nil {
				return false, "", err
			}
```

**File:** test_e2e.sh (L3283-3358)
```shellscript
function e2e::submodule_sync_over_ssh_different_keys() {
    # Init nested submodule repo
    local nested_submodule_repo_name="nested-sub"
    local nested_submodule="$WORK/$nested_submodule_repo_name"
    mkdir "$nested_submodule"

    git -C "$nested_submodule" init -q -b "$MAIN_BRANCH"
    echo "nested-submodule" > "$nested_submodule/nested-submodule.file"
    git -C "$nested_submodule" add nested-submodule.file
    git -C "$nested_submodule" commit -aqm "init nested-submodule.file"

    # Run a git-over-SSH server.  Use key #1.
    local ctr_subsub
    ctr_subsub=$(docker_run \
        -v "$DOT_SSH/server/1":/dot_ssh:ro \
        -v "$nested_submodule":/git/repo:ro \
        e2e/test/sshd)
    local ip_subsub
    ip_subsub=$(docker_ip "$ctr_subsub")

    # Tell local git not to do host checking and to use the test keys.
    export GIT_SSH_COMMAND="ssh -F none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $DOT_SSH/1/id_local -i $DOT_SSH/2/id_local"

    # Init submodule repo
    local submodule_repo_name="sub"
    local submodule="$WORK/$submodule_repo_name"
    mkdir "$submodule"

    git -C "$submodule" init -q -b "$MAIN_BRANCH"
    echo "submodule" > "$submodule/submodule.file"
    git -C "$submodule" add submodule.file
    git -C "$submodule" commit -aqm "init submodule.file"

    # Add nested submodule to submodule repo
    git -C "$submodule" submodule add -q "test@$ip_subsub:/git/repo" "$nested_submodule_repo_name"
    git -C "$submodule" commit -aqm "add nested submodule"

    # Run a git-over-SSH server.  Use key #2.
    local ctr_sub
    ctr_sub=$(docker_run \
        -v "$DOT_SSH/server/2":/dot_ssh:ro \
        -v "$submodule":/git/repo:ro \
        e2e/test/sshd)
    local ip_sub
    ip_sub=$(docker_ip "$ctr_sub")

    # Add the submodule to the main repo
    git -C "$REPO" submodule add -q "test@$ip_sub:/git/repo" "$submodule_repo_name"
    git -C "$REPO" commit -aqm "add submodule"
    git -C "$REPO" submodule update --recursive --remote > /dev/null 2>&1

    # Run a git-over-SSH server.  Use key #3.
    local ctr
    ctr=$(docker_run \
        -v "$DOT_SSH/server/3":/dot_ssh:ro \
        -v "$REPO":/git/repo:ro \
        e2e/test/sshd)
    local ip
    ip=$(docker_ip "$ctr")

    GIT_SYNC \
        --period=100ms \
        --repo="test@$ip:/git/repo" \
        --root="$ROOT" \
        --link="link" \
        --ssh-key-file="/ssh/secret.1" \
        --ssh-key-file="/ssh/secret.2" \
        --ssh-key-file="/ssh/secret.3" \
        --ssh-known-hosts=false \
        &
    wait_for_sync "${MAXWAIT}"
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_exists "$ROOT/link/$submodule_repo_name/submodule.file"
    assert_file_exists "$ROOT/link/$submodule_repo_name/$nested_submodule_repo_name/nested-submodule.file"
    assert_metric_eq "${METRIC_GOOD_SYNC_COUNT}" 1
```

**File:** README.md (L249-256)
```markdown
    --credential <string>, $GITSYNC_CREDENTIAL
            Make one or more credentials available for authentication (see git
            help credential).  This is similar to --username and
            $GITSYNC_PASSWORD or --password-file, but for specific URLs, for
            example when using submodules.  The value for this flag is either a
            JSON-encoded object (see the schema below) or a JSON-encoded list
            of that same object type.  This flag may be specified more than
            once.
```

**File:** README.md (L620-624)
```markdown
            When using submodules it may be necessary to specify more than one
            username and password, which can be done with --credential
            ($GITSYNC_CREDENTIAL).  All of the username+password pairs, from
            both --username/$GITSYNC_PASSWORD and --credential are fed into
            'git credential approve'.
```
