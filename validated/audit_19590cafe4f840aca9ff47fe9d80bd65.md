### Title
Unrestricted `git submodule update` protocol handling allows attacker-controlled repo content to trigger unauthorized submodule fetches - (File: main.go)

### Summary
`git-sync`'s `configureWorktree()` runs `git submodule update --init [--recursive] [--depth N]` against whatever `.gitmodules` content is present in the currently-fetched commit, with no restriction on submodule URL schemes/protocols and no operator confirmation step, analogous to the reported issue: a function reachable via untrusted/unprivileged input (there, `claimAndDistributeRewards()`; here, arbitrary commits landing on the tracked ref) triggers a sensitive action (there, `swap()`; here, submodule fetch/checkout) without any additional access control or validation of what is being acted upon.

### Finding Description
`repoSync.configureWorktree()` unconditionally executes submodule initialization/update using arguments built only from the `--submodules` flag and `--depth`, without any protocol allow-list or `GIT_ALLOW_PROTOCOL`/`protocol.*.allow` restriction being set anywhere in `main.go`: [1](#0-0) 

Because `--submodules` defaults to `recursive`, any commit landing on the synced ref/branch (which git-sync fetches and checks out automatically once per `--period`) can introduce or modify a `.gitmodules` file that points at attacker-chosen URLs/schemes (e.g. `file://`, `ext::`, or arbitrary remote hosts), and git-sync will fetch/execute against them the next time it syncs, with no admin gate in between: [2](#0-1) 

The credential subsystem is explicitly designed to hand out multiple stored credentials for "specific URLs, for example when using submodules," which increases the blast radius if a submodule URL is attacker-controlled and matches a credential-scoped URL prefix: [3](#0-2) 

The `SyncRepo` loop itself has no access-control checkpoint between "new commit observed on ref" and "worktree configured / submodules updated" — it is a fully automatic, unauthenticated pipeline from repo content to local execution of git submodule machinery: [4](#0-3) 

### Impact Explanation
If an attacker can get a commit merged/pushed to the tracked ref (e.g. a low-privilege contributor, a compromised PR-merge bot, or anyone with write access to a branch that isn't `--ref`'s protected default), they can add/modify `.gitmodules` entries to point at malicious repository URLs. Depending on the git version and any host-level git config (which this repo does not manage or restrict), this can result in:
- Server-side request/fetch against attacker-chosen hosts (credential/URL disclosure via `redactURL`-unprotected submodule fetch attempts).
- Reuse of stored, potentially broader-scoped credentials against attacker-controlled endpoints if the submodule URL happens to match a `--credential` URL prefix.
- On older/misconfigured git installations, command execution via dangerous submodule URL schemes (the class of bug fixed upstream by git's own protocol allow-listing, which git-sync does not additionally enforce or document).

This is a lower-likelihood, defense-in-depth style gap (git's own protocol defaults mitigate the worst outcomes on modern git), but the underlying architectural issue mirrors the report exactly: an unprivileged/attacker-influenced trigger (repo content) drives a sensitive operation (submodule fetch, potentially with privileged credentials) with no independent authorization check.

### Likelihood Explanation
Likelihood depends entirely on the deployment: it requires the tracked ref to accept commits from a party less trusted than the git-sync operator (e.g. tracking a PR branch, a shared/team branch, or a repo where write access is broader than the "admin" who configured git-sync's flags/credentials). In such setups the trigger is trivial and automatic (`--submodules=recursive` is the default), and requires no interaction with git-sync itself beyond pushing a commit.

### Recommendation
- Default `--submodules` handling should not run with unrestrained protocol acceptance; consider setting `protocol.*.allow=never` (allow-listing only `https`/`ssh`) for the submodule update git invocation, or explicitly exposing/documenting a flag to restrict allowed submodule URL schemes.
- Document clearly that `--repo`/`--ref` should only ever point at refs where all committers are trusted to the same level as the git-sync credentials configured, since submodule content is fetched and executed with no additional gate.
- Consider adding an explicit opt-in flag before following `.gitmodules`-declared URLs that differ in host/scheme from the primary `--repo`.

### Proof of Concept
1. Attacker with push access to the tracked branch adds a `.gitmodules` entry pointing a submodule at an attacker-controlled or credential-matching URL (as demonstrated by the project's own e2e tests using `file://` submodule URLs): [5](#0-4) 
2. git-sync's next periodic sync fetches the new commit and, in `configureWorktree`, runs `git submodule update --init --recursive` against the attacker-supplied `.gitmodules`, with no protocol restriction applied by git-sync: [6](#0-5) 
3. Depending on git version/config, this results in fetches to attacker-controlled targets (potential credential exposure) or worse, entirely outside the operator's intended `--repo` trust boundary — mirroring the report's core issue of a sensitive action being triggered by untrusted/unprivileged input with no added access control.

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

**File:** main.go (L1929-1946)
```go
		// If we have a new hash, make a new worktree
		newWorktree := currentWorktree
		if changed {
			// Create a worktree for this hash in git.root.
			if wt, err := git.createWorktree(ctx, remoteHash); err != nil {
				return false, "", err
			} else {
				newWorktree = wt
			}
		}

		// Even if this worktree existed and passes sanity, it might not have all
		// the correct settings (e.g. sparse checkout).  The best way to get
		// it all set is just to re-run the configuration,
		if err := git.configureWorktree(ctx, newWorktree); err != nil {
			return false, "", err
		}

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

**File:** README.md (L527-529)
```markdown
    --submodules <string>, $GITSYNC_SUBMODULES
            The git submodule behavior: one of "recursive", "shallow", or
            "off".  If not specified, this defaults to "recursive".
```

**File:** test_e2e.sh (L3004-3005)
```shellscript
    git -C "$REPO" -c protocol.file.allow=always submodule add -q file://$submodule "$submodule_repo_name"
    git -C "$REPO" commit -aqm "add submodule"
```
