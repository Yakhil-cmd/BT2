# Q1448: [allow_all] `GIT_EXEC_PATH` during git clone via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_all`, can an unprivileged fork PR set `GIT_EXEC_PATH` via a pull request label name (uppercased) so `StackCommands#git_clone (git clone --recursive)` executes attacker code, given the git subprocess redirects git subcommand resolution to an attacker directory?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_EXEC_PATH` via a pull request label name (uppercased), git op `StackCommands#git_clone (git clone --recursive)` under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `StackCommands#git_clone (git clone --recursive)` inherits `GIT_EXEC_PATH` and redirects git subcommand resolution to an attacker directory
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_EXEC_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: set `GIT_EXEC_PATH` via a pull request label name (uppercased), assert the Command for `StackCommands#git_clone (git clone --recursive)` passes it to git.
