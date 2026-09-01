# Q0519: [prevent_with_label] `GIT_CONFIG_GLOBAL` during git clone local via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR set `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml` so `TaskCommands#clone (git clone --local)` executes attacker code, given the git subprocess supplies an attacker git config file defining a hook or fsmonitor command git executes?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml`, git op `TaskCommands#clone (git clone --local)` under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `TaskCommands#clone (git clone --local)` inherits `GIT_CONFIG_GLOBAL` and supplies an attacker git config file defining a hook or fsmonitor command git executes
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_CONFIG_GLOBAL`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: set `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the Command for `TaskCommands#clone (git clone --local)` passes it to git.
