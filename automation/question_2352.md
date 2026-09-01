# Q2352: [allow_with_label] `SSH_ASKPASS` during git checkout via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_with_label`, can an unprivileged fork PR set `SSH_ASKPASS` via a pull request label name (uppercased) so `TaskCommands#checkout (git checkout)` executes attacker code, given the git subprocess names a program executed to answer ssh password prompts?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `SSH_ASKPASS` via a pull request label name (uppercased), git op `TaskCommands#checkout (git checkout)` under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `TaskCommands#checkout (git checkout)` inherits `SSH_ASKPASS` and names a program executed to answer ssh password prompts
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `SSH_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: set `SSH_ASKPASS` via a pull request label name (uppercased), assert the Command for `TaskCommands#checkout (git checkout)` passes it to git.
