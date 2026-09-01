# Q1147: [prevent_with_label] `BUNDLE_PATH` in a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`prevent_with_label`, when the review stack runs a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`, can `BUNDLE_PATH` set through a `machine.environment` entry in the fork branch's `shipit.yml` cause execution because the ruby toolchain honours loader variables in the inherited env and redirects bundler to an attacker-populated vendored gem tree that runs on load?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `BUNDLE_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml` under `prevent_with_label`, executed via a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`
- Exploit idea: the ruby toolchain honours loader variables in the inherited env; `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `BUNDLE_PATH` redirects bundler to an attacker-populated vendored gem tree that runs on load
- Invariant to test: No fork-controllable key alters a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: inject `BUNDLE_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert it reaches the a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` process env.
