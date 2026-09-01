# Q4040: [prevent_with_label] `GIT_CONFIG_COUNT` during git checkout via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR set `GIT_CONFIG_COUNT` via a `machine.environment` entry in the fork branch's `shipit.yml` so `TaskCommands#checkout (git checkout)` executes attacker code, given the git subprocess with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_CONFIG_COUNT` via a `machine.environment` entry in the fork branch's `shipit.yml`, git op `TaskCommands#checkout (git checkout)` under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `TaskCommands#checkout (git checkout)` inherits `GIT_CONFIG_COUNT` and with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_CONFIG_COUNT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: set `GIT_CONFIG_COUNT` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the Command for `TaskCommands#checkout (git checkout)` passes it to git.
