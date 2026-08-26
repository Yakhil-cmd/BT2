# Q0180: ReRun — ready latch stale under touch file

## Question
Starting from `--touch-file` used as a readiness gate by the consumer, can an attacker who makes every sync after the first fail (deleted ref, stalled remote, wedged repo) drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where setRepoReady() has already latched true, so `/` keeps returning 200 while the served tree ages indefinitely, defeating “readiness reflects the freshness of the published data, not merely that one sync once succeeded” and causing silent staleness: consumers and orchestration believe data is current when it is not?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Makes every sync after the first fail (deleted ref, stalled remote, wedged repo). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: setRepoReady() has already latched true, so `/` keeps returning 200 while the served tree ages indefinitely
- Invariant to test: readiness reflects the freshness of the published data, not merely that one sync once succeeded
- Expected Immunefi impact: silent staleness: consumers and orchestration believe data is current when it is not (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
