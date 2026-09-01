# Q5691: [prevent_with_label] `GIT_SSH_COMMAND` during git clone via a pull request label name (uppercased)

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR set `GIT_SSH_COMMAND` via a pull request label name (uppercased) so `StackCommands#git_clone (git clone --recursive)` executes attacker code, given the git subprocess replaces the ssh program git invokes with an arbitrary command during fetch/clone?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_SSH_COMMAND` via a pull request label name (uppercased), git op `StackCommands#git_clone (git clone --recursive)` under `prevent_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `StackCommands#git_clone (git clone --recursive)` inherits `GIT_SSH_COMMAND` and replaces the ssh program git invokes with an arbitrary command during fetch/clone
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_SSH_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: set `GIT_SSH_COMMAND` via a pull request label name (uppercased), assert the Command for `StackCommands#git_clone (git clone --recursive)` passes it to git.
