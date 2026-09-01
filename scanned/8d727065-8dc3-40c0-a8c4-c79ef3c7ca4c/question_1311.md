# Q1311: `GIT_SSH_COMMAND` hijacks `git fetch origin` (git) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `git fetch origin` step, can an unprivileged fork PR author set `GIT_SSH_COMMAND` through a pull request label name (uppercased) so the git process replaces the ssh program git invokes with an arbitrary command during fetch/clone?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `GIT_SSH_COMMAND` via a pull request label name (uppercased), with the deploy spec step `git fetch origin`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `GIT_SSH_COMMAND` unfiltered into the `git fetch origin` subprocess, which replaces the ssh program git invokes with an arbitrary command during fetch/clone
- Invariant to test: The `git fetch origin` subprocess inherits no fork-controllable environment key such as `GIT_SSH_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `git fetch origin` and injected `GIT_SSH_COMMAND`, assert Command#unbundled_env passes `GIT_SSH_COMMAND` to the spawned process.
