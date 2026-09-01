# Q4967: [allow_with_label] `GIT_TEMPLATE_DIR` during git clone local via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_with_label`, can an unprivileged fork PR set `GIT_TEMPLATE_DIR` via a pull request label name (uppercased) so `TaskCommands#clone (git clone --local)` executes attacker code, given the git subprocess supplies a template dir whose hooks are copied into and run on the next `git clone`?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_TEMPLATE_DIR` via a pull request label name (uppercased), git op `TaskCommands#clone (git clone --local)` under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `TaskCommands#clone (git clone --local)` inherits `GIT_TEMPLATE_DIR` and supplies a template dir whose hooks are copied into and run on the next `git clone`
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_TEMPLATE_DIR`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: set `GIT_TEMPLATE_DIR` via a pull request label name (uppercased), assert the Command for `TaskCommands#clone (git clone --local)` passes it to git.
