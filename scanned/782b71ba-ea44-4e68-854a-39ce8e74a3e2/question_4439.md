# Q4439: [allow_all] `GIT_ASKPASS` during fetch deployed revision via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_all`, can an unprivileged fork PR set `GIT_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml` so `StackCommands#fetch_deployed_revision` executes attacker code, given the git subprocess points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`, git op `StackCommands#fetch_deployed_revision` under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `StackCommands#fetch_deployed_revision` inherits `GIT_ASKPASS` and points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: set `GIT_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the Command for `StackCommands#fetch_deployed_revision` passes it to git.
