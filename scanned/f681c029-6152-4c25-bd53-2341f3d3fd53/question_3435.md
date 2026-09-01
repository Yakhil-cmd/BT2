# Q3435: `GIT_ASKPASS` executes during git clone via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR author set `GIT_ASKPASS` via a pull request label name (uppercased) so that when `StackCommands#git_clone (git clone --recursive)` runs on the review-stack deploy host, the git subprocess points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `GIT_ASKPASS` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the git subprocess in `StackCommands#git_clone (git clone --recursive)` inherits `GIT_ASKPASS` from Command#unbundled_env and points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `GIT_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `GIT_ASKPASS` on the stack env, assert Command built for `StackCommands#git_clone (git clone --recursive)` passes it to the git subprocess.
