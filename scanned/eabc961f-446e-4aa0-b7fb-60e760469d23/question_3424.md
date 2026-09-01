# Q3424: `GIT_CONFIG_COUNT` hijacks `git fetch origin` (git) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `git fetch origin` step, can an unprivileged fork PR author set `GIT_CONFIG_COUNT` through a pull request label name (uppercased) so the git process with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `GIT_CONFIG_COUNT` via a pull request label name (uppercased), with the deploy spec step `git fetch origin`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `GIT_CONFIG_COUNT` unfiltered into the `git fetch origin` subprocess, which with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command
- Invariant to test: The `git fetch origin` subprocess inherits no fork-controllable environment key such as `GIT_CONFIG_COUNT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `git fetch origin` and injected `GIT_CONFIG_COUNT`, assert Command#unbundled_env passes `GIT_CONFIG_COUNT` to the spawned process.
