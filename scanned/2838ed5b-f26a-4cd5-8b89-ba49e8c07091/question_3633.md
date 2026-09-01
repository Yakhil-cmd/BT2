# Q3633: `GEM_PATH` hijacks `rake deploy` (ruby) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `rake deploy` step, can an unprivileged fork PR author set `GEM_PATH` through a `machine.environment` entry in the fork branch's `shipit.yml` so the ruby process adds an attacker gem path consulted by `require`/`bundle`?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `GEM_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `rake deploy`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `GEM_PATH` unfiltered into the `rake deploy` subprocess, which adds an attacker gem path consulted by `require`/`bundle`
- Invariant to test: The `rake deploy` subprocess inherits no fork-controllable environment key such as `GEM_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `rake deploy` and injected `GEM_PATH`, assert Command#unbundled_env passes `GEM_PATH` to the spawned process.
