# Q1582: [allow_all] `GIT_PROXY_COMMAND` in a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_all`, when the review stack runs a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`, can `GIT_PROXY_COMMAND` set through a `machine.environment` entry in the fork branch's `shipit.yml` cause execution because the ruby toolchain honours loader variables in the inherited env and names an arbitrary command git runs to open transport connections?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `GIT_PROXY_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml` under `allow_all`, executed via a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`
- Exploit idea: the ruby toolchain honours loader variables in the inherited env; `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `GIT_PROXY_COMMAND` names an arbitrary command git runs to open transport connections
- Invariant to test: No fork-controllable key alters a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: inject `GIT_PROXY_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert it reaches the a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` process env.
