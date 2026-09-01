# Q3243: [allow_all] `GIT_CONFIG_COUNT` in a `git` invocation in `StackCommands#fetch`/`#git_clone` via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_all`, when the review stack runs a `git` invocation in `StackCommands#fetch`/`#git_clone`, can `GIT_CONFIG_COUNT` set through a `machine.environment` entry in the fork branch's `shipit.yml` cause execution because the git subprocess inherits the merged env and honours attacker-set git variables and with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `GIT_CONFIG_COUNT` via a `machine.environment` entry in the fork branch's `shipit.yml` under `allow_all`, executed via a `git` invocation in `StackCommands#fetch`/`#git_clone`
- Exploit idea: the git subprocess inherits the merged env and honours attacker-set git variables; `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `GIT_CONFIG_COUNT` with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command
- Invariant to test: No fork-controllable key alters a `git` invocation in `StackCommands#fetch`/`#git_clone`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: inject `GIT_CONFIG_COUNT` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert it reaches the a `git` invocation in `StackCommands#fetch`/`#git_clone` process env.
