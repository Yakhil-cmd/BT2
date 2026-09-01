# Q2985: [allow_with_label] `GIT_CONFIG_GLOBAL` in a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_with_label`, when the review stack runs a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`, can `GIT_CONFIG_GLOBAL` set through a pull request label name (uppercased) cause execution because the ruby toolchain honours loader variables in the inherited env and supplies an attacker git config file defining a hook or fsmonitor command git executes?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `GIT_CONFIG_GLOBAL` via a pull request label name (uppercased) under `allow_with_label`, executed via a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`
- Exploit idea: the ruby toolchain honours loader variables in the inherited env; `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `GIT_CONFIG_GLOBAL` supplies an attacker git config file defining a hook or fsmonitor command git executes
- Invariant to test: No fork-controllable key alters a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: inject `GIT_CONFIG_GLOBAL` via a pull request label name (uppercased), assert it reaches the a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` process env.
