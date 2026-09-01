# Q2746: `GIT_TEMPLATE_DIR` executes during git clone local via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR author set `GIT_TEMPLATE_DIR` via a pull request label name (uppercased) so that when `TaskCommands#clone (git clone --local)` runs on the review-stack deploy host, the git subprocess supplies a template dir whose hooks are copied into and run on the next `git clone`?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `GIT_TEMPLATE_DIR` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the git subprocess in `TaskCommands#clone (git clone --local)` inherits `GIT_TEMPLATE_DIR` from Command#unbundled_env and supplies a template dir whose hooks are copied into and run on the next `git clone`
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `GIT_TEMPLATE_DIR`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `GIT_TEMPLATE_DIR` on the stack env, assert Command built for `TaskCommands#clone (git clone --local)` passes it to the git subprocess.
