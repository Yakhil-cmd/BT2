# Q3351: `GIT_SSH` executes during fetch deployed revision via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR author set `GIT_SSH` via a pull request label name (uppercased) so that when `StackCommands#fetch_deployed_revision` runs on the review-stack deploy host, the git subprocess names an arbitrary program git executes for ssh transport?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `GIT_SSH` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the git subprocess in `StackCommands#fetch_deployed_revision` inherits `GIT_SSH` from Command#unbundled_env and names an arbitrary program git executes for ssh transport
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `GIT_SSH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `GIT_SSH` on the stack env, assert Command built for `StackCommands#fetch_deployed_revision` passes it to the git subprocess.
