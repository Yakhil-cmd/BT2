# Q3895: `SHELL` hijacks `make deploy` (make/shell) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `make deploy` step, can an unprivileged fork PR author set `SHELL` through a `machine.environment` entry in the fork branch's `shipit.yml` so the make/shell process changes the shell binary used to interpret a step, redirecting execution to an attacker program?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `SHELL` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `make deploy`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `SHELL` unfiltered into the `make deploy` subprocess, which changes the shell binary used to interpret a step, redirecting execution to an attacker program
- Invariant to test: The `make deploy` subprocess inherits no fork-controllable environment key such as `SHELL`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `make deploy` and injected `SHELL`, assert Command#unbundled_env passes `SHELL` to the spawned process.
