# Q3337: [allow_all] `GIT_SSH` during git clone local via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_all`, can an unprivileged fork PR set `GIT_SSH` via a `machine.environment` entry in the fork branch's `shipit.yml` so `TaskCommands#clone (git clone --local)` executes attacker code, given the git subprocess names an arbitrary program git executes for ssh transport?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_SSH` via a `machine.environment` entry in the fork branch's `shipit.yml`, git op `TaskCommands#clone (git clone --local)` under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `TaskCommands#clone (git clone --local)` inherits `GIT_SSH` and names an arbitrary program git executes for ssh transport
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_SSH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: set `GIT_SSH` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the Command for `TaskCommands#clone (git clone --local)` passes it to git.
