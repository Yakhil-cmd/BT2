# Q3342: [prevent_with_label] `GIT_PROXY_COMMAND` during git fetch via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR set `GIT_PROXY_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml` so `StackCommands#fetch (git fetch origin)` executes attacker code, given the git subprocess names an arbitrary command git runs to open transport connections?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_PROXY_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`, git op `StackCommands#fetch (git fetch origin)` under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `StackCommands#fetch (git fetch origin)` inherits `GIT_PROXY_COMMAND` and names an arbitrary command git runs to open transport connections
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_PROXY_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: set `GIT_PROXY_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the Command for `StackCommands#fetch (git fetch origin)` passes it to git.
