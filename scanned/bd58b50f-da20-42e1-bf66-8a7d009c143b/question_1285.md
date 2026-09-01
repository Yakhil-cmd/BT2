# Q1285: [allow_all] `GIT_SSH` during git checkout via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_all`, can an unprivileged fork PR set `GIT_SSH` via a pull request label name (uppercased) so `TaskCommands#checkout (git checkout)` executes attacker code, given the git subprocess names an arbitrary program git executes for ssh transport?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_SSH` via a pull request label name (uppercased), git op `TaskCommands#checkout (git checkout)` under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `TaskCommands#checkout (git checkout)` inherits `GIT_SSH` and names an arbitrary program git executes for ssh transport
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_SSH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: set `GIT_SSH` via a pull request label name (uppercased), assert the Command for `TaskCommands#checkout (git checkout)` passes it to git.
