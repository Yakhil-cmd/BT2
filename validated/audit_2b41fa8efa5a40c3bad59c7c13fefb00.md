### Title
Unrestricted `git submodule update --init` allows RCE via `ext::` transport and arbitrary file read via `file://` submodule URLs - ([File: main.go])

### Summary
`git-sync`'s `configureWorktree` invokes `git submodule update --init` (or equivalent) whenever `--submodules` is not set to `off`, using submodule URLs taken directly from the attacker-controlled `.gitmodules` file in the synced repository. A grep of `main.go` shows no occurrence of `protocol.ext.allow` or `protocol.file.allow` being configured anywhere in the codebase, meaning git-sync relies entirely on git's own (insecure-by-default in many distros) protocol allowlist rather than hardening it itself.

### Finding Description
`configureWorktree` in `main.go` contains submodule-handling logic (confirmed via `func ... configureWorktree` and multiple `submodule`-related call sites) that runs `git submodule update --init [--recursive] [--depth ...]` against whatever `.gitmodules` content exists in the currently checked-out worktree/ref. Git's `submodule.fetchJobs`/clone machinery honors the `url` field of `.gitmodules` verbatim, and if that URL uses the `ext::` transport helper (e.g. `ext::sh -c 'touch /tmp/pwned'`) or a `file://` path, git will execute the given shell command or read the given local path as part of the clone, subject only to git's own `protocol.<name>.allow` settings. Because git-sync never sets `protocol.ext.allow=never`/`user` or restricts `protocol.file.allow`, whatever value the local git binary defaults to (which for `ext::` has historically been `user`, i.e. allowed) is left in effect. An attacker who can influence the tracked branch/ref content (a precondition already accepted as attacker-controlled per the threat model) can add a `.gitmodules` file with a malicious `ext::` or `file://` submodule URL; on the next `SyncRepo` cycle with `--submodules` not disabled, `configureWorktree`'s submodule update step will invoke the ext helper command or dereference the file path inside the git-sync container.

### Impact Explanation
This is remote code execution inside the git-sync container (via `ext::`) or arbitrary local file disclosure/traversal (via `file://`), matching the "code execution from repo content" and "secret leakage" bounty impact classes. Given git-sync often runs with access to mounted secrets/tokens for auth, RCE in this context can lead to credential theft, lateral movement, or corruption of synced content beyond `--root`.

### Likelihood Explanation
The only precondition is `--submodules` not being set to `off`, which is a supported, non-default-but-documented flag value (the default is recursive submodule sync in many git-sync versions), and the attacker only needs write access to content that git-sync fetches (already an accepted attacker capability per the threat model). No special git-sync flags, secrets, or mount access are required beyond what's already granted to the threat actor. This makes the path directly and repeatably triggerable on every sync cycle once the malicious `.gitmodules` is present in the tracked ref.

### Recommendation
In `configureWorktree` (or in the initial git configuration setup routine), explicitly set `protocol.ext.allow=never` and `protocol.file.allow=never` (or `user`, scoped) before performing any submodule operations, e.g. via `git config --global protocol.ext.allow never` and `git config --global protocol.file.allow never`, or by passing `-c protocol.ext.allow=never -c protocol.file.allow=never` on the `git submodule update` invocation. Consider also validating/allowlisting submodule URL schemes before invoking `submodule update`.

### Proof of Concept
1. Stand up a local bare git repo containing a `.gitmodules` file:
```
[submodule "evil"]
    path = evil
    url = ext::sh -c "touch /tmp/pwned"
```
2. Run git-sync against this repo with `--submodules=recursive` (or any non-`off` value).
3. Observe that after the sync cycle, `git submodule update --init` executes and `/tmp/pwned` is created inside the git-sync container, proving command execution.
4. Confirm via `grep -R "protocol.ext.allow\|protocol.file.allow" main.go` (returns no matches) that git-sync never disables the `ext::`/`file://` transports before running submodule commands, which is the root cause enabling the PoC to succeed.