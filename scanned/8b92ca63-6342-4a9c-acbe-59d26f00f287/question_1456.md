# Q1456: `SSH_ASKPASS` executes during git fetch sha via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR author set `SSH_ASKPASS` via a pull request label name (uppercased) so that when `StackCommands#fetch_commit (git fetch <sha>)` runs on the review-stack deploy host, the git subprocess names a program executed to answer ssh password prompts?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `SSH_ASKPASS` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the git subprocess in `StackCommands#fetch_commit (git fetch <sha>)` inherits `SSH_ASKPASS` from Command#unbundled_env and names a program executed to answer ssh password prompts
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `SSH_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `SSH_ASKPASS` on the stack env, assert Command built for `StackCommands#fetch_commit (git fetch <sha>)` passes it to the git subprocess.
