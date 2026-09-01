# Q2914: [allow_all] `LD_PRELOAD` in a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_all`, when the review stack runs a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`, can `LD_PRELOAD` set through a pull request label name (uppercased) cause execution because the ruby toolchain honours loader variables in the inherited env and preloads an attacker shared object into every process the deploy spawns?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `LD_PRELOAD` via a pull request label name (uppercased) under `allow_all`, executed via a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`
- Exploit idea: the ruby toolchain honours loader variables in the inherited env; `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `LD_PRELOAD` preloads an attacker shared object into every process the deploy spawns
- Invariant to test: No fork-controllable key alters a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: inject `LD_PRELOAD` via a pull request label name (uppercased), assert it reaches the a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` process env.
