# Q1882: [allow_with_label] `GIT_PROXY_COMMAND` during fetch deployed revision via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_with_label`, can an unprivileged fork PR set `GIT_PROXY_COMMAND` via a pull request label name (uppercased) so `StackCommands#fetch_deployed_revision` executes attacker code, given the git subprocess names an arbitrary command git runs to open transport connections?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_PROXY_COMMAND` via a pull request label name (uppercased), git op `StackCommands#fetch_deployed_revision` under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `StackCommands#fetch_deployed_revision` inherits `GIT_PROXY_COMMAND` and names an arbitrary command git runs to open transport connections
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_PROXY_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: set `GIT_PROXY_COMMAND` via a pull request label name (uppercased), assert the Command for `StackCommands#fetch_deployed_revision` passes it to git.
