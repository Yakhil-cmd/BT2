# Q2169: [allow_all] `GIT_CONFIG_GLOBAL` during git clone local via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_all`, can an unprivileged fork PR set `GIT_CONFIG_GLOBAL` via a pull request label name (uppercased) so `TaskCommands#clone (git clone --local)` executes attacker code, given the git subprocess supplies an attacker git config file defining a hook or fsmonitor command git executes?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_CONFIG_GLOBAL` via a pull request label name (uppercased), git op `TaskCommands#clone (git clone --local)` under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `TaskCommands#clone (git clone --local)` inherits `GIT_CONFIG_GLOBAL` and supplies an attacker git config file defining a hook or fsmonitor command git executes
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_CONFIG_GLOBAL`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: set `GIT_CONFIG_GLOBAL` via a pull request label name (uppercased), assert the Command for `TaskCommands#clone (git clone --local)` passes it to git.
