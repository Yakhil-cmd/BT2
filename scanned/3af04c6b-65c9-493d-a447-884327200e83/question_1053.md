# Q1053: Concrete `GIT_CONFIG_COUNT=1 (+ GIT_CONFIG_KEY_0=core.fsm` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `GIT_CONFIG_COUNT` to `1 (+ GIT_CONFIG_KEY_0=core.fsmonitor, GIT_CONFIG_VALUE_0=touch /tmp/pwn)` through a pull request label name (uppercased), so the review-stack deploy process executes it because it with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `GIT_CONFIG_COUNT=1 (+ GIT_CONFIG_KEY_0=core.fsmonitor, GIT_CONFIG_VALUE_0=touch /tmp/pwn)` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `1 (+ GIT_CONFIG_KEY_0=core.fsmonitor, GIT_CONFIG_VALUE_0=touch /tmp/pwn)` with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command
- Invariant to test: No spawned deploy process ever sees a fork-controlled `GIT_CONFIG_COUNT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `GIT_CONFIG_COUNT=1 (+ GIT_CONFIG_KEY_0=core.fsmonitor, GIT_CONFIG_VALUE_0=touch /tmp/pwn)`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
