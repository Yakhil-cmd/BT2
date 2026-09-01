# Q2094: [prevent_with_label] `GIT_TEMPLATE_DIR` during git fetch sha via a pull request label name (uppercased)

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR set `GIT_TEMPLATE_DIR` via a pull request label name (uppercased) so `StackCommands#fetch_commit (git fetch <sha>)` executes attacker code, given the git subprocess supplies a template dir whose hooks are copied into and run on the next `git clone`?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_TEMPLATE_DIR` via a pull request label name (uppercased), git op `StackCommands#fetch_commit (git fetch <sha>)` under `prevent_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `StackCommands#fetch_commit (git fetch <sha>)` inherits `GIT_TEMPLATE_DIR` and supplies a template dir whose hooks are copied into and run on the next `git clone`
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_TEMPLATE_DIR`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: set `GIT_TEMPLATE_DIR` via a pull request label name (uppercased), assert the Command for `StackCommands#fetch_commit (git fetch <sha>)` passes it to git.
