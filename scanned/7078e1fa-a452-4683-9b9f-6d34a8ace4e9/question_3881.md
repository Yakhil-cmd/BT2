# Q3881: [allow_all] `LD_LIBRARY_PATH` in a `git` invocation in `StackCommands#fetch`/`#git_clone` via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_all`, when the review stack runs a `git` invocation in `StackCommands#fetch`/`#git_clone`, can `LD_LIBRARY_PATH` set through a pull request label name (uppercased) cause execution because the git subprocess inherits the merged env and honours attacker-set git variables and redirects dynamic linking to attacker libraries for spawned binaries?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `LD_LIBRARY_PATH` via a pull request label name (uppercased) under `allow_all`, executed via a `git` invocation in `StackCommands#fetch`/`#git_clone`
- Exploit idea: the git subprocess inherits the merged env and honours attacker-set git variables; `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `LD_LIBRARY_PATH` redirects dynamic linking to attacker libraries for spawned binaries
- Invariant to test: No fork-controllable key alters a `git` invocation in `StackCommands#fetch`/`#git_clone`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: inject `LD_LIBRARY_PATH` via a pull request label name (uppercased), assert it reaches the a `git` invocation in `StackCommands#fetch`/`#git_clone` process env.
