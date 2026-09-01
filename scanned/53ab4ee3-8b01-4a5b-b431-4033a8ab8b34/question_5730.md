# Q5730: `GIT_SSH` hijacks `git fetch origin` (git) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `git fetch origin` step, can an unprivileged fork PR author set `GIT_SSH` through a pull request label name (uppercased) so the git process names an arbitrary program git executes for ssh transport?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `GIT_SSH` via a pull request label name (uppercased), with the deploy spec step `git fetch origin`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `GIT_SSH` unfiltered into the `git fetch origin` subprocess, which names an arbitrary program git executes for ssh transport
- Invariant to test: The `git fetch origin` subprocess inherits no fork-controllable environment key such as `GIT_SSH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `git fetch origin` and injected `GIT_SSH`, assert Command#unbundled_env passes `GIT_SSH` to the spawned process.
