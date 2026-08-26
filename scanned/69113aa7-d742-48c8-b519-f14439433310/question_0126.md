# Q0126: Logger.Error — ready latch stale under error file

## Question
Can an unprivileged attacker who makes every sync after the first fail (deleted ref, stalled remote, wedged repo), under `--error-file` inside --root, read by the consumer as a health signal, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — setRepoReady() has already latched true, so `/` keeps returning 200 while the served tree ages indefinitely, breaking the invariant that readiness reflects the freshness of the published data, not merely that one sync once succeeded and yielding silent staleness: consumers and orchestration believe data is current when it is not?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Makes every sync after the first fail (deleted ref, stalled remote, wedged repo). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: setRepoReady() has already latched true, so `/` keeps returning 200 while the served tree ages indefinitely
- Invariant to test: readiness reflects the freshness of the published data, not merely that one sync once succeeded
- Expected Immunefi impact: silent staleness: consumers and orchestration believe data is current when it is not (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
