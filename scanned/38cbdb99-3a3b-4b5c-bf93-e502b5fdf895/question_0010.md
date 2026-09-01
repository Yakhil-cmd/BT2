# Q0010: `GIT_PROXY_COMMAND` executes during git fetch via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR author set `GIT_PROXY_COMMAND` via a pull request label name (uppercased) so that when `StackCommands#fetch (git fetch origin)` runs on the review-stack deploy host, the git subprocess names an arbitrary command git runs to open transport connections?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `GIT_PROXY_COMMAND` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the git subprocess in `StackCommands#fetch (git fetch origin)` inherits `GIT_PROXY_COMMAND` from Command#unbundled_env and names an arbitrary command git runs to open transport connections
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `GIT_PROXY_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `GIT_PROXY_COMMAND` on the stack env, assert Command built for `StackCommands#fetch (git fetch origin)` passes it to the git subprocess.
