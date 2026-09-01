# Q0774: `GIT_EXEC_PATH` hijacks `git fetch origin` (git) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `git fetch origin` step, can an unprivileged fork PR author set `GIT_EXEC_PATH` through a pull request label name (uppercased) so the git process redirects git subcommand resolution to an attacker directory?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `GIT_EXEC_PATH` via a pull request label name (uppercased), with the deploy spec step `git fetch origin`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `GIT_EXEC_PATH` unfiltered into the `git fetch origin` subprocess, which redirects git subcommand resolution to an attacker directory
- Invariant to test: The `git fetch origin` subprocess inherits no fork-controllable environment key such as `GIT_EXEC_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `git fetch origin` and injected `GIT_EXEC_PATH`, assert Command#unbundled_env passes `GIT_EXEC_PATH` to the spawned process.
