# Q5009: `BASH_ENV` hijacks `make deploy` (make/shell) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `make deploy` step, can an unprivileged fork PR author set `BASH_ENV` through a `machine.environment` entry in the fork branch's `shipit.yml` so the make/shell process names a file bash sources before running a non-interactive `shipit.yml` step?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `BASH_ENV` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `make deploy`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `BASH_ENV` unfiltered into the `make deploy` subprocess, which names a file bash sources before running a non-interactive `shipit.yml` step
- Invariant to test: The `make deploy` subprocess inherits no fork-controllable environment key such as `BASH_ENV`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `make deploy` and injected `BASH_ENV`, assert Command#unbundled_env passes `BASH_ENV` to the spawned process.
