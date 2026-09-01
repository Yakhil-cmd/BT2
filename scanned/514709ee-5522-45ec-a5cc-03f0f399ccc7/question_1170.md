# Q1170: `GIT_SSH_COMMAND` hijacks `git fetch origin` (git) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `git fetch origin` step, can an unprivileged fork PR author set `GIT_SSH_COMMAND` through a `machine.environment` entry in the fork branch's `shipit.yml` so the git process replaces the ssh program git invokes with an arbitrary command during fetch/clone?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `GIT_SSH_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `git fetch origin`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `GIT_SSH_COMMAND` unfiltered into the `git fetch origin` subprocess, which replaces the ssh program git invokes with an arbitrary command during fetch/clone
- Invariant to test: The `git fetch origin` subprocess inherits no fork-controllable environment key such as `GIT_SSH_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `git fetch origin` and injected `GIT_SSH_COMMAND`, assert Command#unbundled_env passes `GIT_SSH_COMMAND` to the spawned process.
