# Q2460: [allow_with_label] `GIT_CONFIG_GLOBAL` during git fetch via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_with_label`, can an unprivileged fork PR set `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml` so `StackCommands#fetch (git fetch origin)` executes attacker code, given the git subprocess supplies an attacker git config file defining a hook or fsmonitor command git executes?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml`, git op `StackCommands#fetch (git fetch origin)` under `allow_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `StackCommands#fetch (git fetch origin)` inherits `GIT_CONFIG_GLOBAL` and supplies an attacker git config file defining a hook or fsmonitor command git executes
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_CONFIG_GLOBAL`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: set `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the Command for `StackCommands#fetch (git fetch origin)` passes it to git.
