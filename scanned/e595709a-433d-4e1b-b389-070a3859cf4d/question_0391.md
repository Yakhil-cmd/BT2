# Q0391: [allow_with_label] `GIT_CONFIG_COUNT` during git clone via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_with_label`, can an unprivileged fork PR set `GIT_CONFIG_COUNT` via a pull request label name (uppercased) so `StackCommands#git_clone (git clone --recursive)` executes attacker code, given the git subprocess with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_CONFIG_COUNT` via a pull request label name (uppercased), git op `StackCommands#git_clone (git clone --recursive)` under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `StackCommands#git_clone (git clone --recursive)` inherits `GIT_CONFIG_COUNT` and with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_CONFIG_COUNT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: set `GIT_CONFIG_COUNT` via a pull request label name (uppercased), assert the Command for `StackCommands#git_clone (git clone --recursive)` passes it to git.
