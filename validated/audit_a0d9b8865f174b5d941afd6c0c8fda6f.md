## Title
SSRF via Attacker-Controlled Submodule URLs in `.gitmodules` — (File: `main.go`)

## Summary
The reported vulnerability class (an application-server making outbound HTTP requests to a URL that an untrusted party fully controls, thereby probing/reaching internal network resources) has a reachable analog in `git-sync`: submodule URLs. `git-sync` automatically runs `git submodule update --init` (optionally `--recursive`) against whatever URLs are declared in the synced repository's `.gitmodules` file, and that file is part of the untrusted content the attacker controls once they can push a commit to (or land content into) the repo/ref being synced.

## Finding Description
`configureWorktree` unconditionally updates submodules whenever submodule syncing is not disabled: [1](#0-0) 

The URLs used for these fetches come entirely from the `.gitmodules` file inside the synced repository content — i.e., from data an attacker who can push a commit (or land a PR/branch that gets synced) fully controls. The project's own end‑to‑end tests demonstrate that arbitrary transport schemes and locations (`file://`, relative paths, nested submodules) are accepted and fetched automatically as part of a normal sync cycle: [2](#0-1) [3](#0-2) 

This mirrors the reported bug class: `git-sync`, acting as a trusted network-connected service (frequently deployed as a sidecar with pod/cluster network access), will issue outbound requests to a location chosen entirely by whoever can influence the synced repo's tree content, not by the operator who configured `--repo`/`--ref`.

## Impact Explanation
Because the submodule URL is resolved and dereferenced by the `git` binary running inside the `git-sync` container/pod, an attacker who can push a `.gitmodules` entry can force the pod to make outbound connections to arbitrary internal-only hosts and ports (e.g., cluster-internal services, or cloud metadata endpoints), which is the classic SSRF impact: internal network reconnaissance/access and potential bypass of network-layer IP allowlisting, since the request originates from a trusted internal host. Depending on git's protocol-allowlist configuration (`protocol.<type>.allow`) in the deployment, this could also be leveraged toward more severe outcomes (e.g., abusing `ext::`/`file://` submodule URLs), but I could not verify from the available code whether `git-sync` overrides git's default protocol allowlist in production (the only `protocol.file.allow=always` setting found is in the e2e test harness invocation, not in production defaults) — this remains unconfirmed and should not be assumed. [4](#0-3) 

## Likelihood Explanation
Exploitability depends entirely on the attacker's ability to get a `.gitmodules` change synced — i.e., push access to the repo/branch `git-sync` follows, or control of a ref/PR that is synced (common in CI/CD or multi-tenant setups where `--repo`/`--ref` track less-trusted branches). This is consistent with the "attacker-pushed commit or ref" threat model this scan is scoped to, not a malicious-operator or leaked-credential scenario.

## Recommendation
- Default `--submodules` to `off` unless explicitly enabled by the operator, and document the SSRF/blast-radius implications of enabling `recursive`/`shallow` submodule syncing for repositories with untrusted contributors.
- When submodules are enabled, restrict allowed protocols for submodule fetches (e.g., set `protocol.file.allow=never` and `protocol.ext.allow=never` by default, only enabling schemes the operator explicitly trusts) rather than relying on git's own defaults.
- Consider adding an allowlist/denylist of permitted submodule URL hosts/schemes enforced by `git-sync` itself before invoking `git submodule update`.

## Proof of Concept
1. Attacker with push access to a branch/ref that `git-sync` is configured to follow adds a `.gitmodules` entry pointing at an internal-only address, e.g.:
   `git submodule add http://169.254.169.254/ evil-sub` (or any internal service URL), then commits and pushes.
2. On the next sync cycle, `git-sync`'s `configureWorktree` runs `git submodule update --init --recursive`, causing the `git-sync` process/pod to issue an outbound request to the attacker-chosen internal address, as shown by the equivalent test flow using `file://` submodule URLs: [5](#0-4)

### Citations

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

**File:** test_e2e.sh (L343-377)
```shellscript
function GIT_SYNC() {
    #./bin/linux_amd64/git-sync "$@"
    local rm="--rm"
    if [[ "${CLEANUP:-}" == 0 ]]; then
        rm=""
    fi
    docker run \
        -i \
        ${rm} `# not quoted on purpose` \
        --label git-sync-e2e="$RUNID" \
        --network="host" \
        -u git-sync:"$(id -g)" `# rely on GID, triggering "dubious ownership"` \
        -v "$ROOT":"$ROOT":rw \
        -v "$REPO":"$REPO":ro \
        -v "$REPO2":"$REPO2":ro \
        -v "$WORK":"$WORK":ro \
        -v "$(pwd)/$TEST_TOOLS":"/$TEST_TOOLS":ro \
        --env "$EXECHOOK_ENVKEY=$EXECHOOK_ENVVAL" \
        -v "$RUNLOG":/var/log/runs \
        -v "$DOT_SSH/1/id_test":"/ssh/secret.1":ro \
        -v "$DOT_SSH/2/id_test":"/ssh/secret.2":ro \
        -v "$DOT_SSH/3/id_test":"/ssh/secret.3":ro \
        "${GITHUB_APP_PRIVATE_KEY_MOUNT[@]}" \
        "${GIT_SYNC_E2E_IMAGE}" \
            -v=6 \
            --add-user \
            --group-write \
            --touch-file="$INTERLOCK" \
            --git-config-add='protocol.file.allow:always' \
            --git-config-add='safe.directory:*' \
            --http-bind=":$HTTP_PORT" \
            --http-metrics \
            --http-pprof \
            "$@"
}
```

**File:** test_e2e.sh (L2982-3017)
```shellscript
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
```

**File:** test_e2e.sh (L3247-3262)
```shellscript
function e2e::submodule_sync_relative() {
    # Init submodule repo
    local submodule_repo_name="sub"
    local submodule="$WORK/$submodule_repo_name"
    mkdir "$submodule"

    git -C "$submodule" init -q -b "$MAIN_BRANCH"
    echo "submodule" > "$submodule/submodule.file"
    git -C "$submodule" add submodule.file
    git -C "$submodule" commit -aqm "init submodule file"

    # Add submodule
    local rel
    rel="$(realpath --relative-to "$REPO" "$WORK/$submodule_repo_name")"
    git -C "$REPO" -c protocol.file.allow=always submodule add -q "$rel" "$submodule_repo_name"
    git -C "$REPO" commit -aqm "add submodule"
```
