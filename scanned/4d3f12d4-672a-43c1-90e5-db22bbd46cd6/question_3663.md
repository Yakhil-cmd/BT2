# Q3663: [prevent_with_label] `GIT_SSH` during fetch deployed revision via a pull request label name (uppercased)

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR set `GIT_SSH` via a pull request label name (uppercased) so `StackCommands#fetch_deployed_revision` executes attacker code, given the git subprocess names an arbitrary program git executes for ssh transport?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_SSH` via a pull request label name (uppercased), git op `StackCommands#fetch_deployed_revision` under `prevent_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `StackCommands#fetch_deployed_revision` inherits `GIT_SSH` and names an arbitrary program git executes for ssh transport
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_SSH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: set `GIT_SSH` via a pull request label name (uppercased), assert the Command for `StackCommands#fetch_deployed_revision` passes it to git.
