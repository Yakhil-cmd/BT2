# Q4333: [allow_all] `SSH_ASKPASS` during git fetch via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_all`, can an unprivileged fork PR set `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml` so `StackCommands#fetch (git fetch origin)` executes attacker code, given the git subprocess names a program executed to answer ssh password prompts?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`, git op `StackCommands#fetch (git fetch origin)` under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `StackCommands#fetch (git fetch origin)` inherits `SSH_ASKPASS` and names a program executed to answer ssh password prompts
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `SSH_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: set `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the Command for `StackCommands#fetch (git fetch origin)` passes it to git.
