# Q0175: `GIT_EXEC_PATH` executes during git fetch via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR author set `GIT_EXEC_PATH` via a pull request label name (uppercased) so that when `StackCommands#fetch (git fetch origin)` runs on the review-stack deploy host, the git subprocess redirects git subcommand resolution to an attacker directory?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `GIT_EXEC_PATH` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the git subprocess in `StackCommands#fetch (git fetch origin)` inherits `GIT_EXEC_PATH` from Command#unbundled_env and redirects git subcommand resolution to an attacker directory
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `GIT_EXEC_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `GIT_EXEC_PATH` on the stack env, assert Command built for `StackCommands#fetch (git fetch origin)` passes it to the git subprocess.
