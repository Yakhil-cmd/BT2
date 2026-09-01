# Q3626: [prevent_with_label] `SSH_ASKPASS` during git checkout via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR set `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml` so `TaskCommands#checkout (git checkout)` executes attacker code, given the git subprocess names a program executed to answer ssh password prompts?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`, git op `TaskCommands#checkout (git checkout)` under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `TaskCommands#checkout (git checkout)` inherits `SSH_ASKPASS` and names a program executed to answer ssh password prompts
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `SSH_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: set `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the Command for `TaskCommands#checkout (git checkout)` passes it to git.
