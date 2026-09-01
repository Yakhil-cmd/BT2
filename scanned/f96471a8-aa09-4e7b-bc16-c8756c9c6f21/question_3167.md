# Q3167: `GIT_CONFIG_COUNT` executes during git checkout via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR author set `GIT_CONFIG_COUNT` via a pull request label name (uppercased) so that when `TaskCommands#checkout (git checkout)` runs on the review-stack deploy host, the git subprocess with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `GIT_CONFIG_COUNT` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the git subprocess in `TaskCommands#checkout (git checkout)` inherits `GIT_CONFIG_COUNT` from Command#unbundled_env and with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `GIT_CONFIG_COUNT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `GIT_CONFIG_COUNT` on the stack env, assert Command built for `TaskCommands#checkout (git checkout)` passes it to the git subprocess.
